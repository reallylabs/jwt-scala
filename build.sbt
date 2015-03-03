name := "jwt-scala"

version := "1.2.1"

organization := "io.really"

crossScalaVersions := Seq("2.10.4", "2.11.0")

homepage := Some(url("https://github.com/reallylabs/jwt-scala"))

licenses += "Apache2" -> url("http://www.opensource.org/licenses/Apache-2.0")

scmInfo := Some(ScmInfo(url("https://github.com/reallylabs/jwt-scala"), "scm:git@github.com:reallylabs/jwt-scala.git"))

publishMavenStyle := true

publishArtifact in Test := false

pomIncludeRepository := { _ => false }

pomExtra := (
  <developers>
    <developer>
      <id>reallylabs</id>
      <name>Really Labs</name>
      <url>http://really.io</url>
    </developer>
  </developers>)

publishTo := {
  val nexus = "https://oss.sonatype.org/"
  if (isSnapshot.value)
    Some("snapshots" at nexus + "content/repositories/snapshots")
  else
    Some("releases" at nexus + "service/local/staging/deploy/maven2")
}

scalaVersion := "2.11.5"

libraryDependencies ++= Seq(
  "org.scalatest" %% "scalatest" % "2.1.5" % "test",
  "com.typesafe.play" %% "play-json" % "2.3.8",
  "commons-codec" % "commons-codec" % "1.6",
  "org.bouncycastle" % "bcprov-jdk16" % "1.46"
)

resolvers ++= Seq(
  "Typesafe Repository" at "http://repo.typesafe.com/typesafe/releases/"
)