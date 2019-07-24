#pragma once
#include <string>

#include <windows.h>

class Event final
{
public:
	Event(const std::string& name, bool manual_reset, bool initial_state);
	virtual ~Event();
	Event(const Event&) = delete;
	Event& operator=(const Event&) = delete;
	Event(Event&&) noexcept = default;
	Event& operator=(Event&&) noexcept = default;

	void set();
	void reset();
	bool is_set();
	
private:
	static HANDLE _s_create_event(const std::string& name, bool manual_reset, bool initial_state);

	HANDLE m_event;
};
