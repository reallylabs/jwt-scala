/**
 * Copyright (C) 2014-2015 Really Inc. <http://really.io>
 */
package io.really.jwt

abstract class JWTException(message: String) extends Exception(message)

/**
 * Represent JWT Exceptions
 */
object JWTException {

  /**
   * Represent Exception that throw when you try decode token contain more than three parts
   */
  class TooManySegments() extends JWTException("Too many segments")

  /**
   * Represent Exception that throw when you try decode token contain less than three parts
   */
  class NotEnoughSegments() extends JWTException("Not enough segment")


  /**
   * Represent Exception that throw when you try to use an invalid key
   */
  class InvalidKey() extends JWTException("Not a valid key ")

  /**
   * Represent Exception that throw when you try to use an invalid public key
   */
  class InvalidPublicKey() extends JWTException("Not a valid public key ")

  /**
   * Represent Exception that throw when you try to use an invalid private key
   */
  class InvalidPrivateKey() extends JWTException("Not a valid private key ")

  /**
   * Represent Exception that throw when you try to use an unknown Algorithm
   */
  class InvalidAlgorithm() extends JWTException("This Algorithm is not valid for this")


}