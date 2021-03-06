#ifndef TRACEY_TRACEY_HPP_INCLUDED
#define TRACEY_TRACEY_HPP_INCLUDED

#include <atomic>
#include <cassert>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifndef _WIN32
#include <unistd.h>
#else
#include <windows.h>
#endif

namespace trc
{

// Our string type
using std::string;
using charptr = const char*;
// Our timekeeping device
using clock = std::chrono::high_resolution_clock;
// Our time designator
using time_point = clock::time_point;
// Our duration type
using duration = clock::duration;

// Process IDs and stuff
#ifndef _WIN32
using process_id = ::pid_t;
#else
using process_id = DWORD;
#endif
// That's part of the stdlib
using thread_id = std::thread::id;
// We can just store arguments as maps of strings
using args_t = std::map<string, string>;

// Phases have names
enum class phase
{
    begin,
    end,
    complete,
    instant,
    counter,
    async_begin,
    async_instant,
    async_end,
    start,
    step,
    finish,
    sample,
    create,
    snapshot,
    destroy,
    meta,
    global_dump,
    process_dump,
    marker,
    clock_sync,
    context,
};

struct event;

// Emit a caller-provided evevnt
inline void emit(const event&);

#ifndef _WIN32
inline process_id current_pid() { return ::getpid(); }
#else
inline process_id current_pid() { return ::GetCurrentProcessId(); }
#endif
inline thread_id current_tid() { return std::this_thread::get_id(); }

struct event
{
    // The event type
    phase ph;
    // The event's name
    charptr name;
    // The categories to which this event belongs
    std::vector<charptr> categories;
    // The time at which the event began
    time_point start;
    // The duration of the event (optional)
    duration dur;
    // The arguments captured with the event
    args_t args;
    // The process ID that owns the event
    process_id pid;
    // The thread ID that owns the event
    thread_id tid;
    // Construct a new event with the given type with the given name
    event(phase ph, charptr name, time_point start = clock::now())
        : ph{ ph }
        , name(name)
        , start{ start }
        , pid{ current_pid() }
        , tid{ current_tid() }
    {
    }
    // Construct a new event with the given type, name, and arguments
    event(phase ph, charptr name, args_t args, time_point ts = clock::now())
        : ph{ ph }
        , name(name)
        , start{ ts }
        , args(std::move(args))
        , pid{ current_pid() }
        , tid{ current_tid() }
    {
    }
    // Construct a complete event with the given name, starting at a certain
    // time with a certain duration
    event(charptr name, time_point start, duration dur, args_t args = {})
        : ph{ phase::complete }
        , name(std::move(name))
        , start{ start }
        , dur{ dur }
        , args(std::move(args))
        , pid{ current_pid() }
        , tid{ current_tid() }
    {
    }
    // Construct an event with the given name, that lasted the given duration
    // (start time is deduced)
    event(charptr name, duration dur, args_t args = {})
        : ph{ phase::complete }
        , name(std::move(name))
        , start{ clock::now() - dur }
        , dur{ dur }
        , args(std::move(args))
        , pid{ current_pid() }
        , tid{ current_tid() }
    {
    }
};

class tracer
{
    struct stream_writer
    {
        virtual void write(const char*, std::streamsize) = 0;
        virtual std::ostream& as_ostream() = 0;
        void write(const char* str) { write(str, std::strlen(str)); }
        template <std::size_t N> void write(const char (&arr)[N])
        {
            write(arr, N - 1);
        }
        template <typename CharTraits, typename Allocator>
        void write(const std::basic_string<char, CharTraits, Allocator>& str)
        {
            write(str.data(), str.size());
        }
        template <typename T> void write_stream(T&& item)
        {
            as_ostream() << std::forward<T>(item);
        }
        virtual ~stream_writer() = default;
    };

    template <typename Stream> struct stream_writer_impl : stream_writer
    {
        Stream strm;
        template <typename T> struct deref_type
        {
            using type = T;
            static type& get(T& t) { return t; }
        };
        template <typename T> struct deref_type<std::reference_wrapper<T>>
        {
            using type = T;
            static type& get(std::reference_wrapper<T> t) { return t.get(); }
        };
        using DerefStream = typename deref_type<Stream>::type;
        void write(const char* bytes, std::streamsize size) override
        {
            auto& stream = deref_type<Stream>::get(strm);
            stream.write(bytes, size);
        }
        std::ostream& as_ostream() override
        {
            auto& stream = deref_type<Stream>::get(strm);
            return stream;
        }

        stream_writer_impl(Stream strm)
            : strm(std::move(strm))
        {
        }
    };

    bool _any_written = false;
    std::unique_ptr<stream_writer> _writer;
    std::vector<event> _events;

    std::chrono::microseconds as_us(time_point tp)
    {
        return as_us(tp.time_since_epoch());
    }

    std::chrono::microseconds as_us(duration dur)
    {
        return std::chrono::duration_cast<std::chrono::microseconds>(dur);
    }

    template <typename... Args> void _write(Args&&... args)
    {
        _writer->write(std::forward<Args>(args)...);
    }

    template <typename T> void _write_stream(T&& item)
    {
        _writer->write_stream(std::forward<T>(item));
    }

    void _write_event(const event& e)
    {
        if (_any_written)
            _write(",");
        _any_written = true;
        _write(R"({"name":)");
        _write("\"");
        _write(e.name);
        _write(R"(","ph":")");
        switch (e.ph)
        {
        case phase::begin:
            _write("B");
            break;
        case phase::end:
            _write("E");
            break;
        case phase::complete:
            _write("X");
            break;
        case phase::instant:
            _write("i");
            break;
        case phase::meta:
            _write("M");
            break;
        default:
            std::terminate();
        }
        _write(R"(","ts":")");
        _write(std::to_string(as_us(e.start).count()));
        _write(R"(","pid":")");
        _write_stream(e.pid);
        _write("\",\"tid\":\"");
        _write_stream(e.tid);
        _write("\"");
        if (!e.args.empty())
        {
            _write(R"(,"args":{)");
            auto first = true;
            for (auto& pair : e.args)
            {
                if (!first)
                    _write(",");
                first = false;
                _write("\"");
                _write(pair.first);
                _write("\": \"");
                _write(pair.second);
                _write("\"");
            }
            _write("}");
        }
        _write("}");
    }

public:
    template <typename Stream>
    tracer(Stream&& strm)
        : _writer{ new stream_writer_impl<Stream>{
              std::forward<Stream>(strm) } }
    {
        _writer->write("[");
    }

    ~tracer()
    {
        flush();
        if (_writer)
            _writer->write("]");
    }

    void emit(const event& e) { _events.push_back(e); }
    void emit(event&& e) { _events.emplace_back(std::move(e)); }

    void flush()
    {
        for (auto& event : _events)
            _write_event(event);
        _events.clear();
    }
};

using tracer_arg_resolver = void (tracer::*)(const char*, const char*);

inline bool enabled();

namespace detail
{

inline std::atomic_bool& enabled_bool()
{
    static std::atomic_bool b;
    static std::once_flag flag;
    std::call_once(flag, [&] { b.store(false); });
    return b;
}

inline std::unique_ptr<tracer>& get_tracer_ptr()
{
    static std::unique_ptr<tracer> ptr;
    return ptr;
}

inline tracer& get_tracer()
{
    auto& ptr = get_tracer_ptr();
    assert(ptr);
    return *ptr;
}

inline std::mutex& get_tracer_lock()
{
    static std::mutex lk;
    return lk;
}

class tracer_locked
{
    tracer* _tracer = nullptr;
    std::unique_lock<std::mutex> _lk;

public:
    tracer_locked(std::unique_lock<std::mutex> lk)
        : _lk{ std::move(lk) }
    {
    }
    tracer_locked(std::unique_lock<std::mutex> lk, tracer& tr)
        : _tracer{ &tr }
        , _lk{ std::move(lk) }
    {
    }

    tracer* operator->()
    {
        assert(_tracer);
        return _tracer;
    }

    explicit operator bool() const { return _tracer != nullptr; }
};

tracer_locked lock_tracer()
{
    std::unique_lock<std::mutex> lk{ get_tracer_lock() };
    if (enabled())
        return { std::move(lk), get_tracer() };
    return { std::move(lk) };
}
}

inline bool enabled() { return detail::enabled_bool().load(); }

template <typename Stream> inline bool enable(Stream&& strm)
{
    auto tr = detail::lock_tracer();
    assert(!tr);
    detail::get_tracer_ptr().reset(new tracer{ std::forward<Stream>(strm) });
    detail::enabled_bool().store(true);
    return true;
}

inline bool disable()
{
    auto tr = detail::lock_tracer();
    if (!tr)
        return false;
    detail::get_tracer_ptr().reset();
    detail::enabled_bool().store(false);
    return true;
}

#define TRC_DOUBLECHECK                                                        \
    if (!::trc::enabled())                                                     \
        return;                                                                \
    auto tr = ::trc::detail::lock_tracer();                                    \
    if (!tr)                                                                   \
        return;


inline void emit(const event& ev)
{
    TRC_DOUBLECHECK;
    tr->emit(ev);
}

inline void start(charptr name, args_t args = {})
{
    emit({ phase::begin, name, args });
}

inline void finish(charptr name, args_t args = {})
{
    emit({ phase::end, name, args });
}

inline void set_process_name(string name)
{
    emit({ phase::meta, "process_name", args_t{ { "name", name } } });
}

inline void set_thread_name(string name)
{
    emit({ phase::meta, "thread_name", args_t{ { "name", name } } });
}

namespace detail
{

class lifetime_tracer
{
    bool _enabled;
    charptr name;

public:
    lifetime_tracer(charptr name)
        : _enabled{ enabled() }
        , name(name)
    {
        if (_enabled)
        {
            emit({ phase::begin, name });
        }
    }

    ~lifetime_tracer()
    {
        if (_enabled)
        {
            emit({ phase::end, name });
        }
    }
};
}
}

#define TRC_PASTE0(a, b) a##b
#define TRC_PASTE(a, b) TRC_PASTE0(a, b)
#define TRC_TRACE_SCOPE(name)                                                  \
    ::trc::detail::lifetime_tracer TRC_PASTE(_tracer, __COUNTER__)(name)
#define TRC_TRACE_FN TRC_TRACE_SCOPE(__func__)

#endif  // TRACEY_TRACEY_HPP_INCLUDED