@echo off
rem sm-maven launcher: runs sm-maven.jar from this folder or its parent (Java 17+ required).
set "DIR=%~dp0"
set "JAR=%DIR%sm-maven.jar"
if not exist "%JAR%" set "JAR=%DIR%..\sm-maven.jar"
if not exist "%JAR%" set "JAR=%DIR%..\build\sm-maven.jar"
if not exist "%JAR%" (echo sm-maven: sm-maven.jar not found 1>&2 & exit /b 3)
set "JAVA=java"
if defined JAVA_HOME set "JAVA=%JAVA_HOME%\bin\java"
"%JAVA%" %SM_MAVEN_JAVA_OPTS% -jar "%JAR%" %*
