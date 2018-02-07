/**
 * Copyright (C) 2014-2015 Really Inc. <http://really.io>
 */
package io.really.jwt

import org.scalatest.{FlatSpec, Matchers}
import play.api.libs.json.Json
import org.apache.commons.codec.binary.Base64


class JWTSpec extends FlatSpec with Matchers {

  "encode" should "generate json web token" in {
    val payload = Json.obj("name" -> "Ahmed", "email" -> "ahmed@gmail.com")
    val jwt = JWT.encode("secret", payload)

    assertResult(JWT.decode(jwt, None).asInstanceOf[JWTResult.JWT].payload)(payload)
  }

  it should "generate json web token with no provided secret" in {
    val payload = Json.obj("name" -> "Ahmed", "email" -> "ahmed@gmail.com")
    val jwt = JWT.encodeWithoutSecret(payload)

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

  it should "decode a token encoded with no secret" in {
    val payload = Json.obj("name" -> "Ahmed", "email" -> "ahmed@gmail.com")
    val jwt = JWT.encodeWithoutSecret(payload)

    val token = JWT.decode(jwt, None).asInstanceOf[JWTResult.JWT]

    assertResult(payload)(token.payload)
    assertResult(Json.obj("alg" -> Algorithm.HS256, "typ" -> "JWT"))(token.header.toJson)
  }

  it should "decode a token encoded with no algorithm" in {
    val payload = Json.obj("name" -> "Ahmed", "email" -> "ahmed@gmail.com")
    val jwt = JWT.encodeWithoutSecret(payload, Json.obj(), Some(Algorithm.NONE))

    val token = JWT.decode(jwt, None).asInstanceOf[JWTResult.JWT]

    assertResult(payload)(token.payload)
    assertResult(Json.obj("alg" -> Algorithm.NONE, "typ" -> "JWT"))(token.header.toJson)
  }

  it should "return Invalid Signature if you try decode singed JWT with crafted None algorithm header" in {
    val payload = Json.obj("name" -> "Test", "email" -> "test@example.com")
    var jwt=JWT.encode("secret",payload)

    val none_header="{\"alg\":\"none\", \"typ\":\"JWT\"}"
    jwt=jwt.replaceAll("^.*?\\.",Base64.encodeBase64URLSafeString(none_header.getBytes("utf-8"))+".");

    assertResult(JWTResult.InvalidSignature)(JWT.decode(jwt, Some("secret")))
  }

}
