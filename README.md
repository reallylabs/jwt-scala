jwt-scala
=========

[![Build Status](https://travis-ci.org/reallylabs/jwt-scala.svg)](https://travis-ci.org/reallylabs/jwt-scala)

An implementation of [JSON Web Tokens](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html)

### Setup
Jwt-scala has been published for scala 2.11/2.10 and sbt 0.13.6

Add the dependency to your build.sbt
```scala
libraryDependencies += "io.really" %% "jwt-scala" % "1.2.2"
```

### Usage

#### Encode
```scala
import io.really.jwt._
import play.api.libs.json.Json

val payload = Json.obj("name" -> "Ahmed", "email" -> "ahmed@gmail.com")
val jwt = JWT.encode("secret-key", payload)
```
By default Encode will use `HS256` Algorithm but you can pass optional Algorithm

```scala
val jwt = JWT.encode("secret-key", payload, Some(Algorithm.HS256))
```
***Supported algorithm are :*** 

- HS256, HS384, HS512
- RS256, RS384, RS512

#### Decode

```scala
val payload = Json.obj("name" -> "Ahmed", "email" -> "ahmed@gmail.com")
val jwt = JWT.encode("secret", payload)

JWT.decode(jwt, Some("secret-1234"))
```

### Licensing
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at [apache licenses](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
