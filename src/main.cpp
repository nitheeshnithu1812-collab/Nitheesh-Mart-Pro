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

    // Health check endpoint - tests DB connection
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

    drogon::app().loadConfigFile("./config.json");
    drogon::app().run();

    return 0;
}
