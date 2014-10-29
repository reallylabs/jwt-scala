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

}