name := "scala-jwt"

version := "1.0"

scalaVersion := "2.11.2"

libraryDependencies ++= Seq(
  "org.scalatest" %% "scalatest" % "2.1.5" % "test",
  "com.typesafe.play" %% "play-json" % "2.3.6",
  "commons-codec" % "commons-codec" % "1.6"
)

resolvers ++= Seq(
  "Typesafe Repository" at "http://repo.typesafe.com/typesafe/releases/"
)