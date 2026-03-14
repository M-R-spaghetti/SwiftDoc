import pathlib

path = pathlib.Path('c:\\Users\\NeveDimka\\Desktop\\antigravity projects\\SwiftDoc\\supabase\\migrations\\00002_security_and_logic_fixes.sql')
text = path.read_text(encoding='utf-16le')

old_code = '''    appt_date     := NEW.scheduled_at::date;
    appt_time     := NEW.scheduled_at::time;
    appt_end_time := (NEW.scheduled_at + (NEW.duration_minutes || \\' minutes\\')::interval)::time;
    -- ISO day of week: Monday=1..Sunday=7, convert to 0=Mon..6=Sun
    appt_dow      := EXTRACT(ISODOW FROM NEW.scheduled_at)::int - 1;'''

new_code = '''    -- FIX: Apply clinic timezone (Asia/Tbilisi) to avoid UTC offset issues during scheduling
    appt_date     := (NEW.scheduled_at AT TIME ZONE \\'Asia/Tbilisi\\')::date;
    appt_time     := (NEW.scheduled_at AT TIME ZONE \\'Asia/Tbilisi\\')::time;
    appt_end_time := ((NEW.scheduled_at + (NEW.duration_minutes || \\' minutes\\')::interval) AT TIME ZONE \\'Asia/Tbilisi\\')::time;
    -- ISO day of week: Monday=1..Sunday=7, convert to 0=Mon..6=Sun
    appt_dow      := EXTRACT(ISODOW FROM (NEW.scheduled_at AT TIME ZONE \\'Asia/Tbilisi\\'))::int - 1;'''

if old_code in text:
    text = text.replace(old_code, new_code)
    path.write_text(text, encoding='utf-16le')
    print('Replaced successfully.')
else:
    print('Could not find old_code.')
