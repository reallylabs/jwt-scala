/**
 * Copyright (C) 2014-2015 Really Inc. <http://really.io>
 */
package io.really.jwt

import org.scalatest.{ShouldMatchers, FlatSpec}
import play.api.libs.json.Json


class JWTSpec extends FlatSpec with ShouldMatchers {

  "encode" should "generate json web token" in {
    val payload = Json.obj("name" -> "Ahmed", "email" -> "ahmed@gmail.com")
    val jwt = JWT.encode("secret", payload)

    assertResult(JWT.decode(jwt, None).asInstanceOf[JWTResult.JWT].payload)(payload)
  }

  "decode" should "decode token and verify it" in {
    val payload = Json.obj("name" -> "Ahmed", "email" -> "ahmed@gmail.com")
    val jwt = JWT.encode("secret", payload)

    val token = JWT.decode(jwt, Some("secret")).asInstanceOf[JWTResult.JWT]

    assertResult(payload)(token.payload)
    assertResult(Json.obj("alg" -> Algorithm.HS256, "typ" -> "JWT"))(token.header.toJson)
  }

  it should "return Invalid Signature if you try decode with incorrect token" in {
    val payload = Json.obj("name" -> "Ahmed", "email" -> "ahmed@gmail.com")
    val jwt = JWT.encode("secret", payload)

    assertResult(JWTResult.InvalidSignature)(JWT.decode(jwt, Some("secret-1234")))
  }

  it should "throw TwoManySegments if you try decode token contain four parts" in {
    val payload = Json.obj("name" -> "Ahmed", "email" -> "ahmed@gmail.com")
    val jwt = s"${JWT.encode("secret", payload)}.Test"

    assertResult(JWTResult.TooManySegments)(JWT.decode(jwt, Some("secret")))
  }

  it should "throw NotEnoughSegments if you try decode token contain one part" in {
    val payload = Json.obj("name" -> "Ahmed", "email" -> "ahmed@gmail.com")
    val jwt = JWT.encodeBase64url(Json.stringify(payload))

    assertResult(JWTResult.NotEnoughSegments)(JWT.decode(jwt, Some("secret")))
  }

  it should "return EmptyJWT if you try decode empty string" in {
    assertResult(JWTResult.EmptyJWT)(JWT.decode("", Some("secret")))
  }

}