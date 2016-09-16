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

using std::string;
using clock = std::chrono::high_resolution_clock;
using time_point = clock::time_point;
using duration = clock::duration;

#ifndef _WIN32
using process_id = ::pid_t;
#else
using process_id = DWORD;
#endif
using thread_id = std::thread::id;
using args_t = std::map<string, string>;


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

inline void emit(const event&);
inline void emit(phase ph, string name, time_point = clock::now());
inline void emit(phase ph, string name, args_t args, time_point = clock::now());
inline void emit(string name, time_point ts, duration dur, args_t args = {});
inline void emit(string name, duration dur, args_t args = {});

#ifndef _WIN32
inline process_id current_pid() { return ::getpid(); }
#else
inline process_id current_pid() { return ::GetCurrentProcessId(); }
#endif
inline thread_id current_tid() { return std::this_thread::get_id(); }

struct event
{
    phase ph;
    string name;
    std::vector<string> categories;
    time_point start;
    duration dur;
    args_t args;
    process_id pid;
    thread_id tid;
    event(phase ph, string name, time_point start = clock::now())
        : ph{ph}
        , name(std::move(name))
        , start{start}
        , pid{current_pid()}
        , tid{current_tid()}
    {
    }
    event(phase ph, string name, args_t args, time_point ts)
        : ph{ph}
        , name(std::move(name))
        , start{ts}
        , args(std::move(args))
        , pid{current_pid()}
        , tid{current_tid()}
    {
    }
    event(string name, time_point start, duration dur, args_t args = {})
        : ph{phase::complete}
        , name(std::move(name))
        , start{start}
        , dur{dur}
        , args(std::move(args))
        , pid{current_pid()}
        , tid{current_tid()}
    {
    }
    event(string name, duration dur, args_t args = {})
        : ph{phase::complete}
        , name(std::move(name))
        , start{clock::now() - dur}
        , dur{dur}
        , args(std::move(args))
        , pid{current_pid()}
        , tid{current_tid()}
    {
    }
};

class tracer
{
    struct stream_writer
    {
        virtual void write(const char*, std::streamsize) = 0;
        virtual std::ostream& as_ostream() = 0;
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
        if (_any_written) _write(",");
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
                if (!first) _write(",");
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
        : _writer{new stream_writer_impl<Stream>{std::forward<Stream>(strm)}}
    {
        _writer->write("[");
    }

    ~tracer()
    {
        flush();
        if (_writer) _writer->write("]");
    }

    void emit(string name, time_point ts, duration dur, args_t args = {});
    void emit(string name, duration dur, args_t args = {});

    void emit(const event& e) { _events.push_back(e); }
    void emit(event&& e) { _events.emplace_back(std::move(e)); }

    void emit(phase ph, string name, time_point ts = clock::now())
    {
        emit(ph, name, {}, ts);
    }

    void emit(phase ph, string name, args_t args, time_point ts = clock::now())
    {
        _events.emplace_back(ph, name, args, ts);
    }

    void flush()
    {
        for (auto& event : _events) _write_event(event);
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
        : _lk{std::move(lk)}
    {
    }
    tracer_locked(std::unique_lock<std::mutex> lk, tracer& tr)
        : _tracer{&tr}
        , _lk{std::move(lk)}
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
    std::unique_lock<std::mutex> lk{get_tracer_lock()};
    if (enabled()) return {std::move(lk), get_tracer()};
    return {std::move(lk)};
}
}

inline bool enabled() { return detail::enabled_bool().load(); }

template <typename Stream> inline bool enable(Stream&& strm)
{
    auto tr = detail::lock_tracer();
    assert(!tr);
    detail::get_tracer_ptr().reset(new tracer{std::forward<Stream>(strm)});
    detail::enabled_bool().store(true);
    return true;
}

inline bool disable()
{
    auto tr = detail::lock_tracer();
    if (!tr) return false;
    detail::get_tracer_ptr().reset();
    detail::enabled_bool().store(false);
    return true;
}

#define TRC_DOUBLECHECK                                                        \
    if (!::trc::enabled()) return;                                             \
    auto tr = ::trc::detail::lock_tracer();                                    \
    if (!tr) return;


inline void emit(const event& ev)
{
    TRC_DOUBLECHECK;
    tr->emit(ev);
}

inline void emit(phase ph, string name, time_point ts)
{
    TRC_DOUBLECHECK;
    tr->emit(ph, name, ts);
}

inline void emit(phase ph, string name, args_t args, time_point ts)
{
    TRC_DOUBLECHECK;
    tr->emit(ph, name, args, ts);
}

inline void emit(string name, time_point ts, duration dur, args_t args)
{
    TRC_DOUBLECHECK;
    tr->emit(name, ts, dur, args);
}

inline void emit(string name, duration dur, args_t args)
{
    TRC_DOUBLECHECK;
    tr->emit(name, dur, args);
}

inline void start(string name, args_t args = {})
{
    emit(phase::begin, name, args);
}

inline void finish(string name, args_t args = {})
{
    emit(phase::end, name, args);
}

inline void set_process_name(string name)
{
    emit(phase::meta, "process_name", args_t{{"name", name}});
}

inline void set_thread_name(string name)
{
    emit(phase::meta, "thread_name", args_t{{"name", name}});
}

namespace detail
{

class lifetime_tracer
{
    bool _enabled;
    string name;

public:
    lifetime_tracer(string name)
        : _enabled{enabled()}
        , name(name)
    {
        if (_enabled)
        {
            emit(phase::begin, name);
        }
    }

    ~lifetime_tracer()
    {
        if (_enabled)
        {
            emit(phase::end, name);
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