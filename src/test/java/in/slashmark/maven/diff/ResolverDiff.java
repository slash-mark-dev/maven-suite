package in.slashmark.maven.diff;

import in.slashmark.maven.model.ModelBuilder;
import in.slashmark.maven.model.Gav;
import in.slashmark.maven.repo.Repos;
import in.slashmark.maven.repo.Settings;
import in.slashmark.maven.resolve.DepNode;
import in.slashmark.maven.resolve.Graph;
import in.slashmark.maven.resolve.Resolver;
import in.slashmark.maven.util.Http;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import org.apache.maven.repository.internal.MavenRepositorySystemUtils;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.collection.CollectRequest;
import org.eclipse.aether.connector.basic.BasicRepositoryConnectorFactory;
import org.eclipse.aether.graph.DependencyNode;
import org.eclipse.aether.impl.DefaultServiceLocator;
import org.eclipse.aether.repository.LocalRepository;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.resolution.ArtifactDescriptorRequest;
import org.eclipse.aether.resolution.ArtifactDescriptorResult;
import org.eclipse.aether.spi.connector.RepositoryConnectorFactory;
import org.eclipse.aether.spi.connector.transport.TransporterFactory;
import org.eclipse.aether.transport.file.FileTransporterFactory;

/** Differential test: our resolver vs Maven's own (maven-resolver 1.9 via maven-resolver-provider 3.9). */
public class ResolverDiff {
    public static void main(String[] args) throws Exception {
        Path fx = Path.of(args[0]);
        String httpBase = args[1];
        DefaultServiceLocator loc = MavenRepositorySystemUtils.newServiceLocator();
        loc.addService(RepositoryConnectorFactory.class, BasicRepositoryConnectorFactory.class);
        loc.addService(TransporterFactory.class, FileTransporterFactory.class);
        RepositorySystem sys = loc.getService(RepositorySystem.class);
        DefaultRepositorySystemSession ses = MavenRepositorySystemUtils.newSession();
        Path local = Files.createTempDirectory("claude-m2");
        ses.setLocalRepositoryManager(sys.newLocalRepositoryManager(ses, new LocalRepository(local.toFile())));
        ses.setChecksumPolicy("ignore");
        ses.setUpdatePolicy("always");
        RemoteRepository central = new RemoteRepository.Builder("central", "default", fx.resolve("repo").toUri().toString()).build();

        Http http = new Http(null);
        Repos repos = new Repos(http, httpBase, null, Settings.empty());
        repos.setUseLocal(false);
        ModelBuilder mb = new ModelBuilder(repos, Map.of(), List.of(), "17");
        Resolver ours = new Resolver(mb);

        File[] roots = fx.resolve("roots").toFile().listFiles();
        Arrays.sort(roots);
        int bad = 0, total = 0, nodes = 0;
        for (File rf : roots) {
            String coords = Files.readString(rf.toPath()).trim();
            if (args.length > 2 && !coords.equals("org.root:" + args[2] + ":1.0")) continue;
            total++;
            // Maven
            ArtifactDescriptorResult desc = sys.readArtifactDescriptor(ses, new ArtifactDescriptorRequest(new DefaultArtifact(coords + "").setVersion(coords.split(":")[2]) , List.of(central), null));
            CollectRequest cr = new CollectRequest();
            cr.setRootArtifact(desc.getArtifact());
            cr.setDependencies(desc.getDependencies());
            cr.setManagedDependencies(desc.getManagedDependencies());
            cr.setRepositories(List.of(central));
            DependencyNode root;
            try {
                root = sys.collectDependencies(ses, cr).getRoot();
            } catch (Throwable e) {
                System.out.println("SKIP " + coords + " (maven failed: " + e.getClass().getSimpleName() + ")");
                continue;
            }
            TreeSet<String> mvn = new TreeSet<>();
            Map<String, String> mvnParent = new TreeMap<>();
            walk(root, null, mvn, mvnParent);
            // Ours
            ModelBuilder.Model m = mb.buildRemote(Gav.parse(coords));
            Graph g = ours.resolve(m, new Resolver.Options());
            TreeSet<String> us = new TreeSet<>();
            Map<String, String> usParent = new TreeMap<>();
            ourWalk(g.direct, null, us, usParent, new HashSet<>());
            nodes += us.size();
            if (!mvn.equals(us) || !mvnParent.equals(usParent)) {
                bad++;
                if (bad <= 8) {
                    System.out.println("MISMATCH " + coords);
                    TreeSet<String> onlyM = new TreeSet<>(mvn); onlyM.removeAll(us);
                    TreeSet<String> onlyU = new TreeSet<>(us); onlyU.removeAll(mvn);
                    System.out.println("  only maven: " + onlyM);
                    System.out.println("  only ours : " + onlyU);
                    for (String k : mvnParent.keySet()) if (!Objects.equals(mvnParent.get(k), usParent.get(k))) System.out.println("  parent of " + k + ": maven=" + mvnParent.get(k) + " ours=" + usParent.get(k));
                    if (args.length > 2) { System.out.println(g.tree(true, true)); dump(root, ""); }
                }
            }
        }
        System.out.println("roots=" + total + " resolvedNodes=" + nodes + " mismatches=" + bad);
        if (bad > 0) System.exit(1);
    }

    static void walk(DependencyNode n, String parent, Set<String> out, Map<String, String> par) {
        for (DependencyNode c : n.getChildren()) {
            var a = c.getArtifact();
            var d = c.getDependency();
            out.add(a.getGroupId() + ":" + a.getArtifactId() + ":" + a.getVersion() + ":" + d.getScope() + (d.isOptional() ? ":optional" : ""));
            par.putIfAbsent(a.getGroupId() + ":" + a.getArtifactId(), parent == null ? "<root>" : parent);
            walk(c, a.getGroupId() + ":" + a.getArtifactId(), out, par);
        }
    }

    static void ourWalk(List<DepNode> nodes, String parent, Set<String> out, Map<String, String> par, Set<DepNode> onPath) {
        for (DepNode n : nodes) {
            if (!n.selected || !onPath.add(n)) continue;
            out.add(n.groupId + ":" + n.artifactId + ":" + n.version + ":" + n.scope + (n.optional ? ":optional" : ""));
            par.putIfAbsent(n.ga(), parent == null ? "<root>" : parent);
            ourWalk(n.kids(), n.ga(), out, par, onPath);
            onPath.remove(n);
        }
    }

    static void dump(DependencyNode n, String ind) {
        for (DependencyNode c : n.getChildren()) {
            System.out.println("M " + ind + c.getArtifact() + " " + c.getDependency().getScope());
            dump(c, ind + "  ");
        }
    }
}
