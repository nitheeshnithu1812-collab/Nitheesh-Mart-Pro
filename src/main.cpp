#include <drogon/drogon.h>
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/nlohmann-json/traits.h>
#include <iostream>

const std::string JWT_SECRET = "nitheesh_mart_secret_key_2026";
using traits = jwt::traits::nlohmann_json;

int main() {
    std::cout << "Nitheesh Mart backend starting..." << std::endl;

    drogon::app().registerHandler(
        "/",
        [](const drogon::HttpRequestPtr &req,
           std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
            Json::Value json;
            json["message"] = "Nitheesh Mart Pro backend is running!";
            json["status"] = "ok";
            auto resp = drogon::HttpResponse::newHttpJsonResponse(json);
            callback(resp);
        },
        {drogon::Get});

    drogon::app().registerHandler(
        "/api/health",
        [](const drogon::HttpRequestPtr &req,
           std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
            auto dbClient = drogon::app().getDbClient();
            Json::Value json;
            if (dbClient) {
                json["database"] = "connected";
                json["status"] = "ok";
            } else {
                json["database"] = "not connected";
                json["status"] = "error";
            }
            auto resp = drogon::HttpResponse::newHttpJsonResponse(json);
            callback(resp);
        },
        {drogon::Get});

    drogon::app().registerHandler(
        "/api/register",
        [](const drogon::HttpRequestPtr &req,
           std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
            auto json = req->getJsonObject();
            Json::Value response;

            if (!json) {
                response["status"] = "error";
                response["message"] = "Invalid JSON body";
                auto resp = drogon::HttpResponse::newHttpJsonResponse(response);
                resp->setStatusCode(drogon::k400BadRequest);
                callback(resp);
                return;
            }

            std::string fullName = (*json)["full_name"].asString();
            std::string email = (*json)["email"].asString();
            std::string password = (*json)["password"].asString();
            std::string phone = (*json).isMember("phone") ? (*json)["phone"].asString() : "";

            if (fullName.empty() || email.empty() || password.empty()) {
                response["status"] = "error";
                response["message"] = "full_name, email, and password are required";
                auto resp = drogon::HttpResponse::newHttpJsonResponse(response);
                resp->setStatusCode(drogon::k400BadRequest);
                callback(resp);
                return;
            }

            std::string hashedPassword = drogon::utils::getSha256(password);

            auto dbClient = drogon::app().getDbClient();
            dbClient->execSqlAsync(
                "INSERT INTO users (full_name, email, phone, password_hash, role_id) VALUES ($1, $2, $3, $4, (SELECT id FROM roles WHERE role_name = 'customer')) RETURNING id, full_name, email",
                [callback](const drogon::orm::Result &result) {
                    Json::Value response;
                    if (result.size() > 0) {
                        response["status"] = "ok";
                        response["message"] = "User registered successfully";
                        response["user_id"] = result[0]["id"].as<int>();
                        response["email"] = result[0]["email"].as<std::string>();
                    }
                    auto resp = drogon::HttpResponse::newHttpJsonResponse(response);
                    callback(resp);
                },
                [callback](const drogon::orm::DrogonDbException &e) {
                    Json::Value response;
                    response["status"] = "error";
                    response["message"] = std::string("Database error: ") + e.base().what();
                    auto resp = drogon::HttpResponse::newHttpJsonResponse(response);
                    resp->setStatusCode(drogon::k500InternalServerError);
                    callback(resp);
                },
                fullName, email, phone, hashedPassword);
        },
        {drogon::Post});

    drogon::app().registerHandler(
        "/api/login",
        [](const drogon::HttpRequestPtr &req,
           std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
            auto json = req->getJsonObject();
            Json::Value response;

            if (!json) {
                response["status"] = "error";
                response["message"] = "Invalid JSON body";
                auto resp = drogon::HttpResponse::newHttpJsonResponse(response);
                resp->setStatusCode(drogon::k400BadRequest);
                callback(resp);
                return;
            }

            std::string email = (*json)["email"].asString();
            std::string password = (*json)["password"].asString();

            if (email.empty() || password.empty()) {
                response["status"] = "error";
                response["message"] = "email and password are required";
                auto resp = drogon::HttpResponse::newHttpJsonResponse(response);
                resp->setStatusCode(drogon::k400BadRequest);
                callback(resp);
                return;
            }

            std::string hashedPassword = drogon::utils::getSha256(password);

            auto dbClient = drogon::app().getDbClient();
            dbClient->execSqlAsync(
                "SELECT id, full_name, email, role_id FROM users WHERE email = $1 AND password_hash = $2",
                [callback, email](const drogon::orm::Result &result) {
                    Json::Value response;
                    if (result.size() == 0) {
                        response["status"] = "error";
                        response["message"] = "Invalid email or password";
                        auto resp = drogon::HttpResponse::newHttpJsonResponse(response);
                        resp->setStatusCode(drogon::k401Unauthorized);
                        callback(resp);
                        return;
                    }

                    int userId = result[0]["id"].as<int>();
                    std::string fullName = result[0]["full_name"].as<std::string>();
                    int roleId = result[0]["role_id"].as<int>();

                    auto token = jwt::create<traits>()
                        .set_type("JWS")
                        .set_issuer("nitheesh-mart")
                        .set_payload_claim("user_id", traits::value_type(std::to_string(userId)))
                        .set_payload_claim("role_id", traits::value_type(std::to_string(roleId)))
                        .sign(jwt::algorithm::hs256{JWT_SECRET});

                    response["status"] = "ok";
                    response["message"] = "Login successful";
                    response["token"] = token;
                    response["user_id"] = userId;
                    response["full_name"] = fullName;
                    response["role_id"] = roleId;

                    auto resp = drogon::HttpResponse::newHttpJsonResponse(response);
                    callback(resp);
                },
                [callback](const drogon::orm::DrogonDbException &e) {
                    Json::Value response;
                    response["status"] = "error";
                    response["message"] = std::string("Database error: ") + e.base().what();
                    auto resp = drogon::HttpResponse::newHttpJsonResponse(response);
                    resp->setStatusCode(drogon::k500InternalServerError);
                    callback(resp);
                },
                email, hashedPassword);
        },
        {drogon::Post});

    drogon::app().loadConfigFile("./config.json");
    drogon::app().run();

    return 0;
}