#include <drogon/drogon.h>
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/nlohmann-json/traits.h>
#include <iostream>

const std::string JWT_SECRET = "nitheesh_mart_secret_key_2026";
using traits = jwt::traits::nlohmann_json;
int getUserIdFromToken(const drogon::HttpRequestPtr& req);

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
    drogon::app().registerHandler(
        "/api/products/search?q={1}",
        [](const drogon::HttpRequestPtr &req,
           std::function<void(const drogon::HttpResponsePtr &)> &&callback,
           std::string query) {
            auto dbClient = drogon::app().getDbClient();
            std::string likeQuery = "%" + query + "%";
            dbClient->execSqlAsync(
                "SELECT id, name, description, price, stock, category_id, seller_id, image_url FROM products WHERE is_active = TRUE AND name ILIKE $1 ORDER BY created_at DESC",
                [callback](const drogon::orm::Result &result) {
                    Json::Value response;
                    Json::Value list(Json::arrayValue);
                    for (const auto &row : result) {
                        Json::Value item;
                        item["id"] = row["id"].as<int>();
                        item["name"] = row["name"].as<std::string>();
                        item["price"] = row["price"].as<std::string>();
                        item["stock"] = row["stock"].as<int>();
                        list.append(item);
                    }
                    response["status"] = "ok";
                    response["results"] = list;
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
                likeQuery);
        },
        {drogon::Get});

    drogon::app().registerHandler(
        "/api/products/{1}",
        [](const drogon::HttpRequestPtr &req,
           std::function<void(const drogon::HttpResponsePtr &)> &&callback,
           int id) {
            auto dbClient = drogon::app().getDbClient();
            dbClient->execSqlAsync(
                "SELECT id, name, description, price, stock, category_id, seller_id, image_url FROM products WHERE id = $1",
                [callback](const drogon::orm::Result &result) {
                    Json::Value response;
                    if (result.size() == 0) {
                        response["status"] = "error";
                        response["message"] = "Product not found";
                        auto resp = drogon::HttpResponse::newHttpJsonResponse(response);
                        resp->setStatusCode(drogon::k404NotFound);
                        callback(resp);
                        return;
                    }
                    const auto &row = result[0];
                    Json::Value item;
                    item["id"] = row["id"].as<int>();
                    item["name"] = row["name"].as<std::string>();
                    item["description"] = row["description"].isNull() ? "" : row["description"].as<std::string>();
                    item["price"] = row["price"].as<std::string>();
                    item["stock"] = row["stock"].as<int>();
                    item["category_id"] = row["category_id"].as<int>();
                    item["seller_id"] = row["seller_id"].as<int>();
                    response["status"] = "ok";
                    response["product"] = item;
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
                id);
        },
        {drogon::Get});

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

    drogon::app().registerHandler(
        "/api/products/{1}",
        [](const drogon::HttpRequestPtr &req,
           std::function<void(const drogon::HttpResponsePtr &)> &&callback,
           int id) {
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
            double price = (*json)["price"].asDouble();
            int stock = (*json)["stock"].asInt();
            auto dbClient = drogon::app().getDbClient();
            dbClient->execSqlAsync(
                "UPDATE products SET name = $1, price = $2, stock = $3 WHERE id = $4 RETURNING id",
                [callback](const drogon::orm::Result &result) {
                    Json::Value response;
                    if (result.size() == 0) {
                        response["status"] = "error";
                        response["message"] = "Product not found";
                        auto resp = drogon::HttpResponse::newHttpJsonResponse(response);
                        resp->setStatusCode(drogon::k404NotFound);
                        callback(resp);
                        return;
                    }
                    response["status"] = "ok";
                    response["message"] = "Product updated";
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
                name, price, stock, id);
        },
        {drogon::Put});

    drogon::app().registerHandler(
        "/api/products/{1}",
        [](const drogon::HttpRequestPtr &req,
           std::function<void(const drogon::HttpResponsePtr &)> &&callback,
           int id) {
            auto dbClient = drogon::app().getDbClient();
            dbClient->execSqlAsync(
                "UPDATE products SET is_active = FALSE WHERE id = $1 RETURNING id",
                [callback](const drogon::orm::Result &result) {
                    Json::Value response;
                    if (result.size() == 0) {
                        response["status"] = "error";
                        response["message"] = "Product not found";
                        auto resp = drogon::HttpResponse::newHttpJsonResponse(response);
                        resp->setStatusCode(drogon::k404NotFound);
                        callback(resp);
                        return;
                    }
                    response["status"] = "ok";
                    response["message"] = "Product deleted";
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
                id);
        },
        {drogon::Delete});

    drogon::app().registerHandler("/api/cart/add",
[](const drogon::HttpRequestPtr &req, std::function<void(const drogon::HttpResponsePtr &)> &&cb) {
    int uid = getUserIdFromToken(req);
    if (uid == -1) {
        Json::Value res; res["status"]="error"; res["message"]="Unauthorized";
        auto resp = drogon::HttpResponse::newHttpJsonResponse(res);
        resp->setStatusCode(drogon::k401Unauthorized); cb(resp); return;
    }
    auto json = req->getJsonObject();
    if (!json || !(*json).isMember("product_id") || !(*json).isMember("quantity")) {
        Json::Value res; res["status"]="error"; res["message"]="product_id and quantity required";
        cb(drogon::HttpResponse::newHttpJsonResponse(res)); return;
    }
    int pid = (*json)["product_id"].asInt();
    int qty = (*json)["quantity"].asInt();
    try {
        auto db = drogon::app().getDbClient();
        int cartId;
        auto r = db->execSqlSync("SELECT id FROM cart WHERE user_id=$1", uid);
        if (r.size() > 0) cartId = r[0]["id"].as<int>();
        else {
            auto r2 = db->execSqlSync("INSERT INTO cart (user_id) VALUES ($1) RETURNING id", uid);
            cartId = r2[0]["id"].as<int>();
        }
        auto r3 = db->execSqlSync("SELECT id, quantity FROM cart_items WHERE cart_id=$1 AND product_id=$2", cartId, pid);
        if (r3.size() > 0) {
            int nq = r3[0]["quantity"].as<int>() + qty;
            db->execSqlSync("UPDATE cart_items SET quantity=$1 WHERE id=$2", nq, r3[0]["id"].as<int>());
        } else {
            db->execSqlSync("INSERT INTO cart_items (cart_id, product_id, quantity) VALUES ($1,$2,$3)", cartId, pid, qty);
        }
        Json::Value res; res["status"]="success"; res["message"]="Item added to cart";
        cb(drogon::HttpResponse::newHttpJsonResponse(res));
    } catch (const drogon::orm::DrogonDbException &e) {
        Json::Value res; res["status"]="error"; res["message"]=e.base().what();
        auto resp = drogon::HttpResponse::newHttpJsonResponse(res);
        resp->setStatusCode(drogon::k500InternalServerError); cb(resp);
    }
}, {drogon::Post});

    drogon::app().registerHandler("/api/cart",
[](const drogon::HttpRequestPtr &req, std::function<void(const drogon::HttpResponsePtr &)> &&cb) {
    int uid = getUserIdFromToken(req);
    if (uid == -1) {
        Json::Value res; res["status"]="error"; res["message"]="Unauthorized";
        auto resp = drogon::HttpResponse::newHttpJsonResponse(res);
        resp->setStatusCode(drogon::k401Unauthorized); cb(resp); return;
    }
    try {
        auto db = drogon::app().getDbClient();
        auto cr = db->execSqlSync("SELECT id FROM cart WHERE user_id=$1", uid);
        Json::Value res; res["status"]="success";
        Json::Value items(Json::arrayValue);
        double total = 0;
        if (cr.size() > 0) {
            int cartId = cr[0]["id"].as<int>();
            auto r = db->execSqlSync(
                "SELECT ci.id, ci.product_id, p.name, p.price, ci.quantity "
                "FROM cart_items ci JOIN products p ON ci.product_id=p.id "
                "WHERE ci.cart_id=$1", cartId);
            for (auto &row : r) {
                Json::Value it;
                it["cart_item_id"] = row["id"].as<int>();
                it["product_id"] = row["product_id"].as<int>();
                it["name"] = row["name"].as<std::string>();
                it["price"] = row["price"].as<double>();
                it["quantity"] = row["quantity"].as<int>();
                total += row["price"].as<double>() * row["quantity"].as<int>();
                items.append(it);
            }
        }
        res["items"] = items;
        res["total"] = total;
        cb(drogon::HttpResponse::newHttpJsonResponse(res));
    } catch (const drogon::orm::DrogonDbException &e) {
        Json::Value res; res["status"]="error"; res["message"]=e.base().what();
        auto resp = drogon::HttpResponse::newHttpJsonResponse(res);
        resp->setStatusCode(drogon::k500InternalServerError); cb(resp);
    }
}, {drogon::Get});

    drogon::app().registerHandler("/api/cart/update/{id}",
[](const drogon::HttpRequestPtr &req, std::function<void(const drogon::HttpResponsePtr &)> &&cb, int id) {
    int uid = getUserIdFromToken(req);
    if (uid == -1) {
        Json::Value res; res["status"]="error"; res["message"]="Unauthorized";
        auto resp = drogon::HttpResponse::newHttpJsonResponse(res);
        resp->setStatusCode(drogon::k401Unauthorized); cb(resp); return;
    }
    auto json = req->getJsonObject();
    if (!json || !(*json).isMember("quantity")) {
        Json::Value res; res["status"]="error"; res["message"]="quantity required";
        cb(drogon::HttpResponse::newHttpJsonResponse(res)); return;
    }
    int qty = (*json)["quantity"].asInt();
    try {
        auto db = drogon::app().getDbClient();
        db->execSqlSync(
            "UPDATE cart_items SET quantity=$1 WHERE id=$2 AND cart_id IN "
            "(SELECT id FROM cart WHERE user_id=$3)", qty, id, uid);
        Json::Value res; res["status"]="success"; res["message"]="Quantity updated";
        cb(drogon::HttpResponse::newHttpJsonResponse(res));
    } catch (const drogon::orm::DrogonDbException &e) {
        Json::Value res; res["status"]="error"; res["message"]=e.base().what();
        auto resp = drogon::HttpResponse::newHttpJsonResponse(res);
        resp->setStatusCode(drogon::k500InternalServerError); cb(resp);
    }
}, {drogon::Put});

    drogon::app().registerHandler("/api/cart/remove/{id}",
[](const drogon::HttpRequestPtr &req, std::function<void(const drogon::HttpResponsePtr &)> &&cb, int id) {
    int uid = getUserIdFromToken(req);
    if (uid == -1) {
        Json::Value res; res["status"]="error"; res["message"]="Unauthorized";
        auto resp = drogon::HttpResponse::newHttpJsonResponse(res);
        resp->setStatusCode(drogon::k401Unauthorized); cb(resp); return;
    }
    try {
        auto db = drogon::app().getDbClient();
        db->execSqlSync(
            "DELETE FROM cart_items WHERE id=$1 AND cart_id IN "
            "(SELECT id FROM cart WHERE user_id=$2)", id, uid);
        Json::Value res; res["status"]="success"; res["message"]="Item removed";
        cb(drogon::HttpResponse::newHttpJsonResponse(res));
    } catch (const drogon::orm::DrogonDbException &e) {
        Json::Value res; res["status"]="error"; res["message"]=e.base().what();
        auto resp = drogon::HttpResponse::newHttpJsonResponse(res);
        resp->setStatusCode(drogon::k500InternalServerError); cb(resp);
    }
}, {drogon::Delete});

    drogon::app().registerHandler("/api/checkout",
[](const drogon::HttpRequestPtr &req, std::function<void(const drogon::HttpResponsePtr &)> &&cb) {
    int uid = getUserIdFromToken(req);
    if (uid == -1) {
        Json::Value res; res["status"]="error"; res["message"]="Unauthorized";
        auto resp = drogon::HttpResponse::newHttpJsonResponse(res);
        resp->setStatusCode(drogon::k401Unauthorized); cb(resp); return;
    }
    auto json = req->getJsonObject();
    if (!json || !(*json).isMember("address_line") || !(*json).isMember("city") ||
        !(*json).isMember("pincode") || !(*json).isMember("phone")) {
        Json::Value res; res["status"]="error"; res["message"]="address_line, city, pincode, phone required";
        cb(drogon::HttpResponse::newHttpJsonResponse(res)); return;
    }
    std::string addr = (*json)["address_line"].asString();
    std::string city = (*json)["city"].asString();
    std::string pin = (*json)["pincode"].asString();
    std::string phone = (*json)["phone"].asString();
    try {
        auto db = drogon::app().getDbClient();
        auto cr = db->execSqlSync("SELECT id FROM cart WHERE user_id=$1", uid);
        if (cr.size() == 0) {
            Json::Value res; res["status"]="error"; res["message"]="Cart is empty";
            cb(drogon::HttpResponse::newHttpJsonResponse(res)); return;
        }
        int cartId = cr[0]["id"].as<int>();
        auto items = db->execSqlSync(
            "SELECT ci.product_id, ci.quantity, p.price FROM cart_items ci "
            "JOIN products p ON ci.product_id=p.id WHERE ci.cart_id=$1", cartId);
        if (items.size() == 0) {
            Json::Value res; res["status"]="error"; res["message"]="Cart is empty";
            cb(drogon::HttpResponse::newHttpJsonResponse(res)); return;
        }
        double total = 0;
        for (auto &row : items) total += row["price"].as<double>() * row["quantity"].as<int>();
        auto orderRes = db->execSqlSync(
            "INSERT INTO orders (user_id,total_amount,address_line,city,pincode,phone) "
            "VALUES ($1,$2,$3,$4,$5,$6) RETURNING id",
            uid, total, addr, city, pin, phone);
        int orderId = orderRes[0]["id"].as<int>();
        for (auto &row : items) {
            db->execSqlSync(
                "INSERT INTO order_items (order_id,product_id,quantity,price) VALUES ($1,$2,$3,$4)",
                orderId, row["product_id"].as<int>(), row["quantity"].as<int>(), row["price"].as<double>());
        }
        db->execSqlSync("DELETE FROM cart_items WHERE cart_id=$1", cartId);
        Json::Value res; res["status"]="success"; res["message"]="Order placed successfully";
        res["order_id"] = orderId; res["total_amount"] = total;
        cb(drogon::HttpResponse::newHttpJsonResponse(res));
    } catch (const drogon::orm::DrogonDbException &e) {
        Json::Value res; res["status"]="error"; res["message"]=e.base().what();
        auto resp = drogon::HttpResponse::newHttpJsonResponse(res);
        resp->setStatusCode(drogon::k500InternalServerError); cb(resp);
    }
}, {drogon::Post});

    drogon::app().loadConfigFile("./config.json");
        drogon::app().registerHandler("/api/orders", [](const drogon::HttpRequestPtr& req, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
        int userId;
        try { userId = getUserIdFromToken(req); }
        catch (...) {
            auto resp = drogon::HttpResponse::newHttpJsonResponse(Json::Value());
            resp->setStatusCode(drogon::k401Unauthorized);
            callback(resp);
            return;
        }
        auto client = drogon::app().getDbClient();
        client->execSqlAsync("SELECT id, total_amount, status, created_at FROM orders WHERE user_id = $1 ORDER BY created_at DESC",
            [callback](const drogon::orm::Result& r) {
                Json::Value arr(Json::arrayValue);
                for (auto row : r) {
                    Json::Value o;
                    o["id"] = row["id"].as<int>();
                    o["total_amount"] = row["total_amount"].as<double>();
                    o["status"] = row["status"].as<std::string>();
                    o["created_at"] = row["created_at"].as<std::string>();
                    arr.append(o);
                }
                callback(drogon::HttpResponse::newHttpJsonResponse(arr));
            },
            [callback](const drogon::orm::DrogonDbException& e) {
                auto resp = drogon::HttpResponse::newHttpJsonResponse(Json::Value());
                resp->setStatusCode(drogon::k500InternalServerError);
                callback(resp);
            }, userId);
    }, {drogon::Get});

        drogon::app().registerHandler("/api/orders/{id}", [](const drogon::HttpRequestPtr& req, std::function<void(const drogon::HttpResponsePtr&)>&& callback, int orderId) {
        int userId;
        try { userId = getUserIdFromToken(req); }
        catch (...) {
            auto resp = drogon::HttpResponse::newHttpJsonResponse(Json::Value());
            resp->setStatusCode(drogon::k401Unauthorized);
            callback(resp);
            return;
        }
        auto client = drogon::app().getDbClient();
        client->execSqlAsync("SELECT id, total_amount, status, created_at FROM orders WHERE id = $1 AND user_id = $2",
            [callback, orderId, client](const drogon::orm::Result& r) {
                if (r.empty()) {
                    auto resp = drogon::HttpResponse::newHttpJsonResponse(Json::Value());
                    resp->setStatusCode(drogon::k404NotFound);
                    callback(resp);
                    return;
                }
                Json::Value order;
                order["id"] = r[0]["id"].as<int>();
                order["total_amount"] = r[0]["total_amount"].as<double>();
                order["status"] = r[0]["status"].as<std::string>();
                order["created_at"] = r[0]["created_at"].as<std::string>();

                client->execSqlAsync("SELECT product_id, quantity, price FROM order_items WHERE order_id = $1",
                    [callback, order](const drogon::orm::Result& r2) mutable {
                        Json::Value items(Json::arrayValue);
                        for (auto row : r2) {
                            Json::Value it;
                            it["product_id"] = row["product_id"].as<int>();
                            it["quantity"] = row["quantity"].as<int>();
                            it["price"] = row["price"].as<double>();
                            items.append(it);
                        }
                        order["items"] = items;
                        callback(drogon::HttpResponse::newHttpJsonResponse(order));
                    },
                    [callback](const drogon::orm::DrogonDbException& e) {
                        auto resp = drogon::HttpResponse::newHttpJsonResponse(Json::Value());
                        resp->setStatusCode(drogon::k500InternalServerError);
                        callback(resp);
                    }, orderId);
            },
            [callback](const drogon::orm::DrogonDbException& e) {
                auto resp = drogon::HttpResponse::newHttpJsonResponse(Json::Value());
                resp->setStatusCode(drogon::k500InternalServerError);
                callback(resp);
            }, orderId, userId);
    }, {drogon::Get});

        drogon::app().registerHandler("/api/orders/{id}/status", [](const drogon::HttpRequestPtr& req, std::function<void(const drogon::HttpResponsePtr&)>&& callback, int orderId) {
        int userId;
        try { userId = getUserIdFromToken(req); }
        catch (...) {
            auto resp = drogon::HttpResponse::newHttpJsonResponse(Json::Value());
            resp->setStatusCode(drogon::k401Unauthorized);
            callback(resp);
            return;
        }
        auto jsonBody = req->getJsonObject();
        if (!jsonBody || !jsonBody->isMember("status")) {
            auto resp = drogon::HttpResponse::newHttpJsonResponse(Json::Value());
            resp->setStatusCode(drogon::k400BadRequest);
            callback(resp);
            return;
        }
        std::string newStatus = (*jsonBody)["status"].asString();
        auto client = drogon::app().getDbClient();
        client->execSqlAsync("UPDATE orders SET status = $1 WHERE id = $2 AND user_id = $3",
            [callback](const drogon::orm::Result& r) {
                Json::Value res;
                res["message"] = "Order status updated";
                callback(drogon::HttpResponse::newHttpJsonResponse(res));
            },
            [callback](const drogon::orm::DrogonDbException& e) {
                auto resp = drogon::HttpResponse::newHttpJsonResponse(Json::Value());
                resp->setStatusCode(drogon::k500InternalServerError);
                callback(resp);
            }, newStatus, orderId, userId);
    }, {drogon::Put});

    drogon::app().run();

    return 0;
}

int getUserIdFromToken(const drogon::HttpRequestPtr& req) {
    auto authHeader = req->getHeader("Authorization");
    if (authHeader.empty() || authHeader.substr(0, 7) != "Bearer ") return -1;
    std::string token = authHeader.substr(7);
    try {
        auto decoded = jwt::decode<traits>(token);
        auto verifier = jwt::verify<jwt::default_clock, traits>({})
            .allow_algorithm(jwt::algorithm::hs256{JWT_SECRET});
        verifier.verify(decoded);
        return std::stoi(decoded.get_payload_json()["user_id"].get<std::string>());
    } catch (...) {
        return -1;
    }
}















