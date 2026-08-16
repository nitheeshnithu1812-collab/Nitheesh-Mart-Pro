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

    // GET all categories
    drogon::app().registerHandler(
        "/api/categories",
        [](const drogon::HttpRequestPtr &req,
           std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
            auto dbClient = drogon::app().getDbClient();
            dbClient->execSqlAsync(
                "SELECT id, name, description FROM categories ORDER BY name",
                [callback](const drogon::orm::Result &result) {
                    Json::Value response;
                    Json::Value list(Json::arrayValue);
                    for (const auto &row : result) {
                        Json::Value item;
                        item["id"] = row["id"].as<int>();
                        item["name"] = row["name"].as<std::string>();
                        item["description"] = row["description"].isNull() ? "" : row["description"].as<std::string>();
                        list.append(item);
                    }
                    response["status"] = "ok";
                    response["categories"] = list;
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
                });
        },
        {drogon::Get});

    // POST create category
    drogon::app().registerHandler(
        "/api/categories",
        [](const drogon::HttpRequestPtr &req,
           std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
            auto json = req->getJsonObject();
            Json::Value response;

            if (!json || (*json)["name"].asString().empty()) {
                response["status"] = "error";
                response["message"] = "name is required";
                auto resp = drogon::HttpResponse::newHttpJsonResponse(response);
                resp->setStatusCode(drogon::k400BadRequest);
                callback(resp);
                return;
            }

            std::string name = (*json)["name"].asString();
            std::string description = (*json).isMember("description") ? (*json)["description"].asString() : "";

            auto dbClient = drogon::app().getDbClient();
            dbClient->execSqlAsync(
                "INSERT INTO categories (name, description) VALUES ($1, $2) RETURNING id, name",
                [callback](const drogon::orm::Result &result) {
                    Json::Value response;
                    response["status"] = "ok";
                    response["message"] = "Category created";
                    response["id"] = result[0]["id"].as<int>();
                    response["name"] = result[0]["name"].as<std::string>();
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
                name, description);
        },
        {drogon::Post});

    // GET all products
    drogon::app().registerHandler(
        "/api/products",
        [](const drogon::HttpRequestPtr &req,
           std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
            auto dbClient = drogon::app().getDbClient();
            dbClient->execSqlAsync(
                "SELECT id, name, description, price, stock, category_id, seller_id, image_url FROM products WHERE is_active = TRUE ORDER BY created_at DESC",
                [callback](const drogon::orm::Result &result) {
                    Json::Value response;
                    Json::Value list(Json::arrayValue);
                    for (const auto &row : result) {
                        Json::Value item;
                        item["id"] = row["id"].as<int>();
                        item["name"] = row["name"].as<std::string>();
                        item["description"] = row["description"].isNull() ? "" : row["description"].as<std::string>();
                        item["price"] = row["price"].as<std::string>();
                        item["stock"] = row["stock"].as<int>();
                        item["category_id"] = row["category_id"].as<int>();
                        item["seller_id"] = row["seller_id"].as<int>();
                        item["image_url"] = row["image_url"].isNull() ? "" : row["image_url"].as<std::string>();
                        list.append(item);
                    }
                    response["status"] = "ok";
                    response["products"] = list;
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
                });
        },
        {drogon::Get});

    // POST create product
    drogon::app().registerHandler(
        "/api/products",
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

            std::string name = (*json)["name"].asString();
            std::string description = (*json).isMember("description") ? (*json)["description"].asString() : "";
            double price = (*json)["price"].asDouble();
            int stock = (*json).isMember("stock") ? (*json)["stock"].asInt() : 0;
            int categoryId = (*json)["category_id"].asInt();
            int sellerId = (*json)["seller_id"].asInt();
            std::string imageUrl = (*json).isMember("image_url") ? (*json)["image_url"].asString() : "";

            if (name.empty() || price <= 0 || categoryId <= 0 || sellerId <= 0) {
                response["status"] = "error";
                response["message"] = "name, price, category_id, seller_id are required";
                auto resp = drogon::HttpResponse::newHttpJsonResponse(response);
                resp->setStatusCode(drogon::k400BadRequest);
                callback(resp);
                return;
            }

            auto dbClient = drogon::app().getDbClient();
            dbClient->execSqlAsync(
                "INSERT INTO products (name, description, price, stock, category_id, seller_id, image_url) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, name",
                [callback](const drogon::orm::Result &result) {
                    Json::Value response;
                    response["status"] = "ok";
                    response["message"] = "Product created";
                    response["id"] = result[0]["id"].as<int>();
                    response["name"] = result[0]["name"].as<std::string>();
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
                name, description, price, stock, categoryId, sellerId, imageUrl);
        },
        {drogon::Post});

    drogon::app().loadConfigFile("./config.json");
    drogon::app().run();

    return 0;
}