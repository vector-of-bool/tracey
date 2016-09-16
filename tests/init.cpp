#include <catch/catch.hpp>

#include <tracey/tracey.hpp>

#include <algorithm>
#include <fstream>
#include <random>
#include <sstream>

TEST_CASE("Can create a tracer")
{
    std::stringstream strm;
    trc::tracer tr{std::move(strm)};
}

TEST_CASE("Can create a tracer from a reference_wrapper")
{
    std::stringstream strm;
    trc::tracer{std::ref(strm)};
    CHECK(strm.str() == "[]");
}

TEST_CASE("Can emit an event")
{
    std::stringstream strm;
    {
        // auto now = trc::clock::now();
        trc::tracer tr{std::ref(strm)};
        std::this_thread::sleep_for(std::chrono::seconds(1));
        tr.emit(trc::phase::instant, "meow");
    }
    CHECK(strm.str() == R"([{"ph":"i","name":"meow","ts":""}])");
}

TEST_CASE("Tracer starts disabled") { CHECK_FALSE(trc::enabled()); }

TEST_CASE("Can enable tracing")
{
    std::stringstream strm;
    CHECK(trc::enable(std::move(strm)));
    CHECK(trc::enabled());
    trc::disable();
}

TEST_CASE("Disable without enable") { CHECK_FALSE(trc::disable()); }

TEST_CASE("Disable after enable")
{
    std::stringstream strm;
    CHECK(trc::enable(std::move(strm)));
    CHECK(trc::disable());
    CHECK_FALSE(trc::disable());
}

TEST_CASE("Trace a function")
{
    std::ofstream of{"trace.json"};
    trc::enable(std::move(of));
    TRC_TRACE_FN;
    TRC_TRACE_SCOPE("Meow");
    TRC_TRACE_SCOPE("Another");
    TRC_TRACE_SCOPE("Another one");
    std::mt19937 mt;
    std::uniform_int_distribution<> dist{0, 3000};
    std::vector<int> nums(3000);
    trc::start("Generate numbers");
    std::generate(nums.begin(), nums.end(), [&] {
        TRC_TRACE_SCOPE("Generate number");
        return dist(mt);
    });
    trc::finish("");
    trc::start("Sort numbers");
    std::sort(nums.begin(), nums.end(), [](int a, int b) {
        TRC_TRACE_SCOPE("Compare numbers");
        return a < b;
    });
    trc::finish("");
}

TEST_CASE("Set thread name")
{
    trc::set_thread_name("Test Runner Thread");
}