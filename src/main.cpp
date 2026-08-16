#include <drogon/drogon.h>
#include <iostream>

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

    drogon::app().loadConfigFile("./config.json");
    drogon::app().run();

    return 0;
}
