# Generate Python code for Time-Based Access Control.


from datetime import datetime

def is_access_allowed(access_schedule):
    """
    Check if access is allowed based on the current time and provided schedule.
    
    Args:
        access_schedule (list of dict): List of access windows with:
            - 'days': list of abbreviated day names (e.g., ['mon', 'tue'])
            - 'start': start time in 'HH:MM' format
            - 'end': end time in 'HH:MM' format
    
    Returns:
        bool: True if access is allowed, False otherwise
    """
    now = datetime.now()
    current_day = now.strftime('%a').lower()
    current_time = now.time()
    
    for window in access_schedule:
        window_days = [day.lower() for day in window['days']]
        if current_day not in window_days:
            continue
        
        start_time = datetime.strptime(window['start'], '%H:%M').time()
        end_time = datetime.strptime(window['end'], '%H:%M').time()
        
        if start_time <= end_time:
            if start_time <= current_time <= end_time:
                return True
        else:
            if current_time >= start_time or current_time <= end_time:
                return True
    
    return False

# Example usage
if __name__ == "__main__":
    access_schedule = [
        {
            'days': ['mon', 'tue', 'wed', 'thu', 'fri'],
            'start': '09:00',
            'end': '17:00'
        },
        {
            'days': ['sat'],
            'start': '10:00',
            'end': '14:00'
        },
        {
            'days': ['fri', 'sat'],
            'start': '20:00',
            'end': '02:00'
        }
    ]
    
    allowed = is_access_allowed(access_schedule)
    print(f"Access currently {'allowed' if allowed else 'denied'}.")