#include <exception>

#include "event.hpp"

Event::Event(const std::string& name, bool manual_reset, bool initial_state) :
    m_event(_s_create_event(name, manual_reset, initial_state))
{}

Event::~Event()
{
    try
    {
        if (m_event)
        {
            CloseHandle(m_event);
            m_event = nullptr;
        }
    }
    catch (...)
    {}
}


void Event::set()
{
    if (!SetEvent(m_event))
    {
        throw std::exception("Unable to set event");
    }
}

void Event::reset()
{
    if (!ResetEvent(m_event))
    {
        throw std::exception("Unable to reset event");
    }
}

bool Event::is_set()
{
    return WaitForSingleObject(m_event, 0) == WAIT_OBJECT_0;
}

HANDLE Event::_s_create_event(const std::string& name, bool manual_reset, bool initial_state)
{
    const HANDLE event = CreateEventA(nullptr, manual_reset, initial_state, name.c_str());
    if (!event)
    {
        throw std::exception("Could not set event");
    }

    return event;
}

