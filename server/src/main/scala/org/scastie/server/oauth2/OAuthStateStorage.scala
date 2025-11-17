package org.scastie.web.oauth2

import scala.collection.mutable
import scala.concurrent.duration._

case class OAuthStateData(redirectUrl: String, expiresAt: Long)

class OAuthStateStorage {
  private val storage = mutable.Map[String, OAuthStateData]()
  private val stateTimeout = 10.minutes.toMillis

  def store(state: String, redirectUrl: String): Unit = {
    synchronized {
      cleanup()
      storage.put(state, OAuthStateData(redirectUrl, System.currentTimeMillis() + stateTimeout))
    }
  }

  def validateAndConsume(state: String): Option[String] = {
    synchronized {
      cleanup()
      storage.remove(state).flatMap { data =>
        if (System.currentTimeMillis() <= data.expiresAt) {
          Some(data.redirectUrl)
        } else {
          None
        }
      }
    }
  }

  private def cleanup(): Unit = {
    val now = System.currentTimeMillis()
    storage.filterInPlace { case (_, data) => data.expiresAt > now }
  }
}
