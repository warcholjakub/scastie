package org.scastie
package web
package routes

import oauth2._

import com.softwaremill.session.SessionDirectives._
import com.softwaremill.session.SessionOptions._
import com.softwaremill.session.CsrfDirectives._
import com.softwaremill.session.CsrfOptions._

import akka.http.scaladsl.model._
import akka.http.scaladsl.model.Uri.Query
import akka.http.scaladsl.model.StatusCodes.TemporaryRedirect
import akka.http.scaladsl.model.headers.Referer
import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.server.Route

import scala.concurrent.ExecutionContext

class OAuth2Routes(github: Github, session: GithubUserSession)(
    implicit val executionContext: ExecutionContext
) {
  import session._

  val routes: Route =
    get(
      concat(
        path("login") {
          parameter("home".?)(
            home =>
              optionalHeaderValueByType[Referer](()) { referrer =>
                val redirectUrl = {
                  val homeUri = "/"
                  if (home.isDefined) homeUri
                  else referrer.map(_.value).getOrElse(homeUri)
                }
                val state = github.generateState()
                github.storeState(state, redirectUrl)
                redirect(
                  Uri("https://github.com/login/oauth/authorize").withQuery(
                    Query(
                      "client_id" -> github.clientId,
                      "state" -> state
                    )
                  ),
                  TemporaryRedirect
                )
            }
          )
        },
        path("logout") {
          headerValueByType[Referer](()) { referrer =>
            requiredSession(refreshable, usingCookies) { _ =>
              invalidateSession(refreshable, usingCookies) { ctx =>
                ctx.complete(
                  HttpResponse(
                    status = TemporaryRedirect,
                    headers = headers.Location(Uri(referrer.value)) :: Nil,
                    entity = HttpEntity.Empty
                  )
                )
              }
            }
          }
        },
        pathPrefix("callback") {
          pathEnd {
            parameters("code", "state") { (code, receivedState) =>
              github.validateAndConsumeState(receivedState) match {
                case Some(redirectUrl) =>
                  onSuccess(github.getUserDataWithOauth2(code)) { userData =>
                    setSession(refreshable, usingCookies, session.addUserData(userData)) {
                      setNewCsrfToken(checkHeader) { ctx =>
                        ctx.complete(
                          HttpResponse(
                            status = TemporaryRedirect,
                            headers = headers.Location(Uri(redirectUrl)) :: Nil,
                            entity = HttpEntity.Empty
                          )
                        )
                      }
                    }
                  }
                case None =>
                  complete(
                    HttpResponse(
                      status = StatusCodes.BadRequest,
                      entity = HttpEntity(
                        ContentTypes.`text/plain(UTF-8)`,
                        "Invalid or expired OAuth state parameter"
                      )
                    )
                  )
              }
            }
          }
        }
      )
    )
}
