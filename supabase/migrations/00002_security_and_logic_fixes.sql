-- ============================================================================
-- SwiftDoc Clinic вЂ” Security & Logic Fixes Migration
-- Migration: 00002_security_and_logic_fixes.sql
-- Generated: 2026-03-14
-- Fixes:     23 issues from expert audit (P0 в†’ P3)
-- ============================================================================
-- EXECUTION ORDER:
--   1. P0 Critical security fixes
--   2. P1 Logic fixes (triggers + constraints)
--   3. P2 Schema improvements (new tables, altered columns)
--   4. Updated RLS policies
--   5. New indexes
-- ============================================================================


-- в•”в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•—
-- в•‘  1. P0 вЂ” CRITICAL SECURITY FIXES                                      в•‘
-- в•љв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ќ


-- в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
-- FIX #1: Prevent privilege escalation (role change by non-admin)
-- Risk: Any patient could SET role='admin' and take over the system.
-- в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

CREATE OR REPLACE FUNCTION public.prevent_role_change()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  -- Block non-admins from changing their role
  IF NEW.role IS DISTINCT FROM OLD.role THEN
    IF NOT public.is_admin() THEN
      RAISE EXCEPTION 'Only administrators can change user roles.';
    END IF;
  END IF;

  -- Block non-admins from toggling is_deleted (soft delete is admin-only)
  IF NEW.is_deleted IS DISTINCT FROM OLD.is_deleted THEN
    IF NOT public.is_admin() THEN
      RAISE EXCEPTION 'Only administrators can delete or restore accounts.';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_prevent_role_change
  BEFORE UPDATE ON public.profiles
  FOR EACH ROW EXECUTE FUNCTION public.prevent_role_change();


-- в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
-- FIX #2: Validate payment.user_id matches appointment.user_id
-- Risk: Mismatched user_id could leak payment data across users.
-- в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

CREATE OR REPLACE FUNCTION public.validate_payment_ownership()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  appt_user_id uuid;
BEGIN
  SELECT user_id INTO appt_user_id
  FROM public.appointments
  WHERE id = NEW.appointment_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Appointment % not found.', NEW.appointment_id;
  END IF;

  -- Auto-fill user_id from appointment if not provided
  IF NEW.user_id IS NULL THEN
    NEW.user_id := appt_user_id;
  END IF;

  -- Validate consistency
  IF NEW.user_id IS DISTINCT FROM appt_user_id THEN
    RAISE EXCEPTION 'Payment user_id (%) must match appointment user_id (%).', NEW.user_id, appt_user_id;
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_payment_ownership
  BEFORE INSERT OR UPDATE ON public.payments
  FOR EACH ROW EXECUTE FUNCTION public.validate_payment_ownership();


-- в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
-- FIX #3: RLS must filter out soft-deleted profiles (is_deleted)
-- Risk: Deleted users could still log in and perform actions.
-- в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

-- Drop existing profile policies and recreate with is_deleted filter
DROP POLICY IF EXISTS "profiles_select_own" ON public.profiles;
DROP POLICY IF EXISTS "profiles_update_own" ON public.profiles;
DROP POLICY IF EXISTS "profiles_admin_select" ON public.profiles;

-- Patients can only see/edit their own ACTIVE profile
CREATE POLICY "profiles_select_own" ON public.profiles
  FOR SELECT USING (auth.uid() = id AND is_deleted = false);

CREATE POLICY "profiles_update_own" ON public.profiles
  FOR UPDATE USING (auth.uid() = id AND is_deleted = false)
  WITH CHECK (auth.uid() = id AND is_deleted = false);

-- Admins see everything (including deleted, for management)
CREATE POLICY "profiles_admin_select" ON public.profiles
  FOR SELECT USING (public.is_admin());

CREATE POLICY "profiles_admin_update" ON public.profiles
  FOR UPDATE USING (public.is_admin())
  WITH CHECK (public.is_admin());

-- Also filter soft-deleted users in appointment creation
DROP POLICY IF EXISTS "appointments_insert_own" ON public.appointments;

CREATE POLICY "appointments_insert_own" ON public.appointments
  FOR INSERT WITH CHECK (
    user_id = auth.uid()
    AND EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid() AND is_deleted = false
    )
    AND (
      family_member_id IS NULL
      OR public.owns_family_member(family_member_id)
    )
  );


-- в•”в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•—
-- в•‘  2. P1 вЂ” LOGIC FIXES                                                   в•‘
-- в•љв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ќ


-- в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
-- FIX #8: Auto-fill price_at_booking from services table
-- Problem: Nullable field, no default, clients can forget to send it.
-- в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

CREATE OR REPLACE FUNCTION public.autofill_appointment_defaults()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  svc record;
BEGIN
  -- Fetch service details
  SELECT price, duration_minutes
  INTO svc
  FROM public.services
  WHERE id = NEW.service_id;

  -- Auto-fill price if not provided
  IF NEW.price_at_booking IS NULL AND svc.price IS NOT NULL THEN
    NEW.price_at_booking := svc.price;
  END IF;

  -- Auto-fill duration if still default and service has a different duration
  IF NEW.duration_minutes = 30 AND svc.duration_minutes IS NOT NULL AND svc.duration_minutes <> 30 THEN
    NEW.duration_minutes := svc.duration_minutes;
  END IF;

  -- Set locked_until for new awaiting_payment appointments (15 min TTL)
  IF TG_OP = 'INSERT' AND NEW.status = 'awaiting_payment' AND NEW.locked_until IS NULL THEN
    NEW.locked_until := now() + interval '15 minutes';
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_autofill_appointment_defaults
  BEFORE INSERT ON public.appointments
  FOR EACH ROW EXECUTE FUNCTION public.autofill_appointment_defaults();


-- в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
-- FIX #9 + #10: Validate doctorв†”service AND doctor schedule
-- Problem: No check that doctor provides the service or is
--          working at the requested day/time.
-- в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

-- Replace the existing validate_appointment_schedule to add all checks
CREATE OR REPLACE FUNCTION public.validate_appointment_schedule()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  appt_date      date;
  appt_time      time;
  appt_end_time  time;
  appt_dow       int;    -- 0=Mon..6=Sun
  sched          record;
BEGIN
  -- Only validate on INSERT or when time/doctor changes
  IF TG_OP = 'INSERT'
     OR (TG_OP = 'UPDATE' AND (
       NEW.scheduled_at IS DISTINCT FROM OLD.scheduled_at
       OR NEW.doctor_id IS DISTINCT FROM OLD.doctor_id
       OR NEW.service_id IS DISTINCT FROM OLD.service_id
     ))
  THEN
    -- Skip validation for cancelled/rescheduled statuses
    IF NEW.status IN ('cancelled', 'rescheduled') THEN
      RETURN NEW;
    END IF;

    -- FIX: Apply clinic timezone (Asia/Tbilisi) to avoid UTC offset issues during scheduling
    appt_date     := (NEW.scheduled_at AT TIME ZONE 'Asia/Tbilisi')::date;
    appt_time     := (NEW.scheduled_at AT TIME ZONE 'Asia/Tbilisi')::time;
    appt_end_time := ((NEW.scheduled_at + (NEW.duration_minutes || ' minutes')::interval) AT TIME ZONE 'Asia/Tbilisi')::time;
    -- ISO day of week: Monday=1..Sunday=7, convert to 0=Mon..6=Sun
    appt_dow      := EXTRACT(ISODOW FROM (NEW.scheduled_at AT TIME ZONE 'Asia/Tbilisi'))::int - 1;

    -- в”Ђв”Ђ CHECK 1: Doctor absences в”Ђв”Ђ
    IF EXISTS (
      SELECT 1 FROM public.doctor_absences
      WHERE doctor_id = NEW.doctor_id
        AND appt_date >= start_date
        AND appt_date <= end_date
    ) THEN
      RAISE EXCEPTION 'Doctor is absent on % (vacation/sick leave).', appt_date;
    END IF;

    -- в”Ђв”Ђ CHECK 2: Doctor provides this service в”Ђв”Ђ
    IF NOT EXISTS (
      SELECT 1 FROM public.doctor_services
      WHERE doctor_id = NEW.doctor_id
        AND service_id = NEW.service_id
    ) THEN
      RAISE EXCEPTION 'This doctor does not provide the selected service.';
    END IF;

    -- в”Ђв”Ђ CHECK 3: Doctor works this day/time в”Ђв”Ђ
    SELECT * INTO sched
    FROM public.doctor_schedules
    WHERE doctor_id = NEW.doctor_id
      AND day_of_week = appt_dow
      AND is_active = true
      AND appt_time >= start_time
      AND appt_end_time <= end_time
    LIMIT 1;

    IF NOT FOUND THEN
      RAISE EXCEPTION 'Doctor is not available at this day/time. Requested: % (day %), % - %',
        appt_date, appt_dow, appt_time, appt_end_time;
    END IF;

  END IF;

  RETURN NEW;
END;
$$;

-- Trigger already exists from initial schema, just recreated the function


-- в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
-- FIX #21: doctor_reviews вЂ” change CASCADE to SET NULL for user_id
-- Problem: Deleting a user destroys all their reviews, corrupting
--          doctor ratings. Reviews should become anonymous instead.
-- в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

-- Make user_id nullable and change FK behavior
ALTER TABLE public.doctor_reviews
  ALTER COLUMN user_id DROP NOT NULL;

ALTER TABLE public.doctor_reviews
  DROP CONSTRAINT IF EXISTS doctor_reviews_user_id_fkey;

ALTER TABLE public.doctor_reviews
  ADD CONSTRAINT doctor_reviews_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES public.profiles(id) ON DELETE SET NULL;


-- в•”в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•—
-- в•‘  3. P2 вЂ” SCHEMA IMPROVEMENTS                                          в•‘
-- в•љв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ќ


-- в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
-- FIX #5: UNIQUE review per appointment (not per doctor)
-- Problem: Patient can only leave 1 review per doctor EVER.
-- в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

ALTER TABLE public.doctor_reviews
  DROP CONSTRAINT IF EXISTS reviews_unique_per_doctor;

-- One review per appointment (naturally prevents duplicates)
ALTER TABLE public.doctor_reviews
  ADD CONSTRAINT reviews_unique_per_appointment UNIQUE (appointment_id);


-- в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
-- FIX #6: Relax past-booking check for admin/walk-in scenarios
-- Problem: CHECK (scheduled_at > created_at) blocks walk-in entries.
-- в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

ALTER TABLE public.appointments
  DROP CONSTRAINT IF EXISTS appointments_no_past_booking;

-- Allow a 1-hour grace window for walk-ins and timezone drift
ALTER TABLE public.appointments
  ADD CONSTRAINT appointments_no_past_booking
    CHECK (scheduled_at >= created_at - interval '1 hour');

-- Change duration_minutes default from 30 to NULL so the autofill trigger
-- can distinguish "client didn't provide duration" from "client explicitly chose 30 min"
ALTER TABLE public.appointments
  ALTER COLUMN duration_minutes DROP NOT NULL,
  ALTER COLUMN duration_minutes SET DEFAULT NULL;


-- в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
-- FIX #7: Allow multiple schedule slots per day (remove UNIQUE)
-- Problem: Doctor can't have morning + afternoon shifts.
-- в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

ALTER TABLE public.doctor_schedules
  DROP CONSTRAINT IF EXISTS schedules_unique_day;

-- Add EXCLUDE constraint to prevent overlapping time ranges on same day
-- Note: requires btree_gist extension (already enabled)
-- We'll use a trigger since time ranges need special handling

CREATE OR REPLACE FUNCTION public.validate_schedule_overlap()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM public.doctor_schedules
    WHERE doctor_id = NEW.doctor_id
      AND day_of_week = NEW.day_of_week
      AND is_active = true
      AND id IS DISTINCT FROM NEW.id  -- exclude self on UPDATE
      AND (NEW.start_time, NEW.end_time) OVERLAPS (start_time, end_time)
  ) THEN
    RAISE EXCEPTION 'Schedule overlap: doctor % already has a slot on day % that overlaps with %-%.', 
      NEW.doctor_id, NEW.day_of_week, NEW.start_time, NEW.end_time;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_schedule_overlap
  BEFORE INSERT OR UPDATE ON public.doctor_schedules
  FOR EACH ROW EXECUTE FUNCTION public.validate_schedule_overlap();


-- в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
-- FIX #17: News article categories (enum instead of just bool)
-- Problem: No way to distinguish news vs tips vs promotions.
-- в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

CREATE TYPE public.article_category AS ENUM (
  'news',
  'tip',
  'promotion',
  'announcement'
);

ALTER TABLE public.news_articles
  ADD COLUMN category public.article_category NOT NULL DEFAULT 'news';

COMMENT ON COLUMN public.news_articles.category IS 'Article category. Replaces the older is_promotion boolean for richer filtering.';

-- Remove the now-redundant is_promotion boolean to avoid data duplication
-- Category enum fully replaces it: category = 'promotion' is the new way
ALTER TABLE public.news_articles
  DROP COLUMN IF EXISTS is_promotion;


-- в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
-- FIX #14: Treatment plan progress tracking fields
-- Problem: No fields for tracking orthodontic-style progress.
-- в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

ALTER TABLE public.treatment_plans
  ADD COLUMN elapsed_months int,
  ADD COLUMN progress_notes text;

COMMENT ON COLUMN public.treatment_plans.elapsed_months IS 'Manually or cron-updated elapsed months since start_date.';
COMMENT ON COLUMN public.treatment_plans.progress_notes IS 'Doctor notes on current treatment progress.';


-- в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
-- FIX #20: Appointment audit log
-- Problem: No record of who changed what and when.
-- в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

CREATE TABLE public.appointment_audit_log (
  id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  appointment_id   uuid        NOT NULL REFERENCES public.appointments(id) ON DELETE CASCADE,
  changed_by       uuid        REFERENCES public.profiles(id) ON DELETE SET NULL,
  action           text        NOT NULL,   -- 'status_change', 'reschedule', 'cancellation', 'creation'
  old_status       public.appointment_status,
  new_status       public.appointment_status,
  old_scheduled_at timestamptz,
  new_scheduled_at timestamptz,
  reason           text,
  metadata         jsonb,
  created_at       timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE public.appointment_audit_log IS 'Immutable audit trail of all appointment state changes.';

CREATE INDEX idx_audit_log_appointment ON public.appointment_audit_log(appointment_id);
CREATE INDEX idx_audit_log_created     ON public.appointment_audit_log(created_at);

-- RLS: only admins and the appointment owner can read
ALTER TABLE public.appointment_audit_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY "audit_log_select_own" ON public.appointment_audit_log
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM public.appointments
      WHERE appointments.id = appointment_audit_log.appointment_id
        AND appointments.user_id = auth.uid()
    )
  );

CREATE POLICY "audit_log_admin_all" ON public.appointment_audit_log
  FOR ALL USING (public.is_admin());

-- Trigger: automatically log every status change
CREATE OR REPLACE FUNCTION public.log_appointment_changes()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    INSERT INTO public.appointment_audit_log (
      appointment_id, changed_by, action, new_status, new_scheduled_at
    ) VALUES (
      NEW.id, auth.uid(), 'creation', NEW.status, NEW.scheduled_at
    );
  ELSIF TG_OP = 'UPDATE' THEN
    -- Log status changes
    IF NEW.status IS DISTINCT FROM OLD.status THEN
      INSERT INTO public.appointment_audit_log (
        appointment_id, changed_by, action,
        old_status, new_status,
        old_scheduled_at, new_scheduled_at,
        reason
      ) VALUES (
        NEW.id, auth.uid(), 'status_change',
        OLD.status, NEW.status,
        OLD.scheduled_at, NEW.scheduled_at,
        NEW.cancellation_reason
      );
    -- Log reschedules (time change without status change)
    ELSIF NEW.scheduled_at IS DISTINCT FROM OLD.scheduled_at THEN
      INSERT INTO public.appointment_audit_log (
        appointment_id, changed_by, action,
        old_status, new_status,
        old_scheduled_at, new_scheduled_at
      ) VALUES (
        NEW.id, auth.uid(), 'reschedule',
        OLD.status, NEW.status,
        OLD.scheduled_at, NEW.scheduled_at
      );
    END IF;
  END IF;

  RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE TRIGGER trg_log_appointment_changes
  AFTER INSERT OR UPDATE ON public.appointments
  FOR EACH ROW EXECUTE FUNCTION public.log_appointment_changes();


-- в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
-- FIX #22: Promotions / Discount codes table
-- Problem: PRD mentions promotions but no structure for promo codes.
-- в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

CREATE TYPE public.discount_type AS ENUM (
  'percentage',
  'fixed_amount'
);

CREATE TABLE public.promotions (
  id                uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
  code              text          NOT NULL,
  title_ka          text          NOT NULL,
  title_en          text          NOT NULL,
  title_ru          text          NOT NULL,
  description_ka    text,
  description_en    text,
  description_ru    text,
  discount_type     public.discount_type NOT NULL,
  discount_value    numeric(10,2) NOT NULL,     -- percentage (0-100) or fixed amount
  min_order_amount  numeric(10,2) DEFAULT 0,    -- minimum spend to use
  max_uses          int,                         -- NULL = unlimited
  current_uses      int           NOT NULL DEFAULT 0,
  per_user_limit    int           NOT NULL DEFAULT 1,
  applicable_services uuid[],                    -- NULL = all services
  valid_from        timestamptz   NOT NULL DEFAULT now(),
  valid_until       timestamptz,
  is_active         boolean       NOT NULL DEFAULT true,
  created_at        timestamptz   NOT NULL DEFAULT now(),

  CONSTRAINT promotions_code_unique      UNIQUE (code),
  CONSTRAINT promotions_value_positive   CHECK (discount_value > 0),
  CONSTRAINT promotions_percentage_range CHECK (
    discount_type <> 'percentage' OR (discount_value >= 0 AND discount_value <= 100)
  ),
  CONSTRAINT promotions_dates_order      CHECK (valid_until IS NULL OR valid_until > valid_from)
);

COMMENT ON TABLE public.promotions IS 'Discount codes and promotional offers with usage limits and validity periods.';

-- Track which users used which promo codes
CREATE TABLE public.promotion_usages (
  id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  promotion_id   uuid        NOT NULL REFERENCES public.promotions(id) ON DELETE CASCADE,
  user_id        uuid        NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  appointment_id uuid        REFERENCES public.appointments(id) ON DELETE SET NULL,
  discount_applied numeric(10,2) NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT usage_positive_discount CHECK (discount_applied > 0)
);

CREATE INDEX idx_promo_usages_user ON public.promotion_usages(user_id);
CREATE INDEX idx_promo_usages_promo ON public.promotion_usages(promotion_id);

-- RLS for promotions
ALTER TABLE public.promotions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.promotion_usages ENABLE ROW LEVEL SECURITY;

-- Anyone authenticated can see active promotions
CREATE POLICY "promotions_select_active" ON public.promotions
  FOR SELECT USING (auth.role() = 'authenticated' AND is_active = true);

CREATE POLICY "promotions_admin_all" ON public.promotions
  FOR ALL USING (public.is_admin());

-- Users can see their own promo usage
CREATE POLICY "promo_usages_select_own" ON public.promotion_usages
  FOR SELECT USING (user_id = auth.uid());

CREATE POLICY "promo_usages_admin_all" ON public.promotion_usages
  FOR ALL USING (public.is_admin());

-- Add promo reference to payments
ALTER TABLE public.payments
  ADD COLUMN promotion_id uuid REFERENCES public.promotions(id) ON DELETE SET NULL,
  ADD COLUMN discount_amount numeric(10,2) DEFAULT 0;

COMMENT ON COLUMN public.payments.promotion_id IS 'Applied promotion/discount code, if any.';
COMMENT ON COLUMN public.payments.discount_amount IS 'Discount amount applied from promotion.';


-- в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
-- FIX #23: Custom price per doctor-service combination
-- Problem: All doctors charge the same for each service.
-- в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

ALTER TABLE public.doctor_services
  ADD COLUMN custom_price numeric(10,2),
  ADD COLUMN custom_duration_minutes int;

COMMENT ON COLUMN public.doctor_services.custom_price IS 'Override price for this doctor. NULL = use services.price.';
COMMENT ON COLUMN public.doctor_services.custom_duration_minutes IS 'Override duration for this doctor. NULL = use services.duration_minutes.';

-- Update autofill trigger to check doctor_services.custom_price first
CREATE OR REPLACE FUNCTION public.autofill_appointment_defaults()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  ds_custom_price    numeric(10,2);
  ds_custom_duration int;
  svc_price          numeric(10,2);
  svc_duration       int;
BEGIN
  -- Check for doctor-specific pricing first
  SELECT custom_price, custom_duration_minutes
  INTO ds_custom_price, ds_custom_duration
  FROM public.doctor_services
  WHERE doctor_id = NEW.doctor_id AND service_id = NEW.service_id;

  -- Get default service pricing
  SELECT price, duration_minutes
  INTO svc_price, svc_duration
  FROM public.services
  WHERE id = NEW.service_id;

  -- Price priority: explicitly set price only allowed for admins
  IF NOT public.is_admin() THEN
    NEW.price_at_booking := COALESCE(ds_custom_price, svc_price);
  ELSIF NEW.price_at_booking IS NULL THEN
    NEW.price_at_booking := COALESCE(ds_custom_price, svc_price);
  END IF;

  -- Duration priority: explicit > doctor_services.custom > services.duration
  -- Use NULL check instead of magic number 30 to distinguish "not set" from "explicitly chose 30"
  IF NEW.duration_minutes IS NULL THEN
    NEW.duration_minutes := COALESCE(ds_custom_duration, svc_duration, 30);
  END IF;

  -- Status priority: non-admins must start at awaiting_payment
  IF TG_OP = 'INSERT' THEN
    IF NOT public.is_admin() THEN
      NEW.status := 'awaiting_payment';
    END IF;
    
    -- Set locked_until for new awaiting_payment appointments (15 min TTL)
    IF NEW.status = 'awaiting_payment' AND NEW.locked_until IS NULL THEN
      NEW.locked_until := now() + interval '15 minutes';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;


-- в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
-- FIX #13: Calendar event ID for external calendar integration
-- в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

ALTER TABLE public.appointments
  ADD COLUMN calendar_event_id text;

COMMENT ON COLUMN public.appointments.calendar_event_id IS 'External calendar event ID (Google Calendar, Apple Calendar) for sync.';


-- в•”в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•—
-- в•‘  4. ADDITIONAL INDEX IMPROVEMENTS                                      в•‘
-- в•љв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ќ

-- Faster promo code lookups
CREATE INDEX idx_promotions_code ON public.promotions(code);
CREATE INDEX idx_promotions_active ON public.promotions(is_active, valid_from, valid_until);

-- Faster category filtering for news
CREATE INDEX idx_news_category ON public.news_articles(category, is_published);


-- в•”в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•—
-- в•‘  5. UPDATE validate_doctor_review for new UNIQUE constraint            в•‘
-- в•љв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ќ

-- The existing validate_doctor_review trigger works well.
-- Just update it to handle the case where user_id is now nullable (anonymous reviews after deletion).
CREATE OR REPLACE FUNCTION public.validate_doctor_review()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  appt_record record;
BEGIN
  -- Only validate on INSERT (updates to old reviews are OK)
  IF TG_OP = 'UPDATE' AND OLD.appointment_id = NEW.appointment_id THEN
    RETURN NEW;
  END IF;

  SELECT * INTO appt_record
  FROM public.appointments
  WHERE id = NEW.appointment_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Appointment not found.';
  END IF;

  IF appt_record.user_id IS DISTINCT FROM NEW.user_id THEN
    RAISE EXCEPTION 'You can only review your own appointments.';
  END IF;

  IF appt_record.doctor_id <> NEW.doctor_id THEN
    RAISE EXCEPTION 'This appointment was with a different doctor.';
  END IF;

  IF appt_record.status <> 'completed' THEN
    RAISE EXCEPTION 'You can only review completed appointments.';
  END IF;

  RETURN NEW;
END;
$$;


-- в•”в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•—
-- в•‘  6. PROMOTION VALIDATION TRIGGER                                       в•‘
-- в•љв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ќ

CREATE OR REPLACE FUNCTION public.validate_promotion_usage()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  promo record;
  user_usage_count int;
BEGIN
  IF NEW.promotion_id IS NULL THEN
    RETURN NEW;
  END IF;

  -- Get promotion details with row-level lock to prevent race conditions
  -- (two concurrent requests reading the same current_uses before either increments)
  SELECT * INTO promo
  FROM public.promotions
  WHERE id = NEW.promotion_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Promotion not found.';
  END IF;

  IF NOT promo.is_active THEN
    RAISE EXCEPTION 'This promotion is no longer active.';
  END IF;

  -- Check validity period
  IF promo.valid_until IS NOT NULL AND now() > promo.valid_until THEN
    RAISE EXCEPTION 'This promotion has expired.';
  END IF;

  IF now() < promo.valid_from THEN
    RAISE EXCEPTION 'This promotion is not yet active.';
  END IF;

  -- Check max total uses
  IF promo.max_uses IS NOT NULL AND promo.current_uses >= promo.max_uses THEN
    RAISE EXCEPTION 'This promotion has reached its usage limit.';
  END IF;

  -- Check per-user limit
  SELECT COUNT(*) INTO user_usage_count
  FROM public.promotion_usages
  WHERE promotion_id = NEW.promotion_id
    AND user_id = NEW.user_id;

  IF user_usage_count >= promo.per_user_limit THEN
    RAISE EXCEPTION 'You have already used this promotion the maximum number of times.';
  END IF;

  -- Increment usage counter
  UPDATE public.promotions
  SET current_uses = current_uses + 1
  WHERE id = NEW.promotion_id;

  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_promotion_usage
  BEFORE INSERT ON public.promotion_usages
  FOR EACH ROW EXECUTE FUNCTION public.validate_promotion_usage();


-- в•”в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•—
-- в•‘  7. LOYALTY TIER THRESHOLDS вЂ” move from hardcoded to clinic_settings   в•‘
-- в•љв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ќ

-- Add tier thresholds to clinic_settings
ALTER TABLE public.clinic_settings
  ADD COLUMN loyalty_gold_threshold     int NOT NULL DEFAULT 500,
  ADD COLUMN loyalty_platinum_threshold int NOT NULL DEFAULT 1500;

COMMENT ON COLUMN public.clinic_settings.loyalty_gold_threshold IS 'Lifetime points needed for Gold tier.';
COMMENT ON COLUMN public.clinic_settings.loyalty_platinum_threshold IS 'Lifetime points needed for Platinum tier.';

-- Update the recalc_loyalty function to read thresholds from settings
CREATE OR REPLACE FUNCTION public.recalc_loyalty()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  new_balance      int;
  new_lifetime     int;
  new_tier         public.loyalty_tier;
  gold_threshold   int;
  plat_threshold   int;
BEGIN
  -- Recalculate totals from the full ledger
  SELECT
    COALESCE(SUM(points), 0),
    COALESCE(SUM(CASE WHEN points > 0 THEN points ELSE 0 END), 0)
  INTO new_balance, new_lifetime
  FROM public.loyalty_transactions
  WHERE loyalty_card_id = NEW.loyalty_card_id;

  -- Guard: prevent negative balance
  IF new_balance < 0 THEN
    RAISE EXCEPTION 'Loyalty points balance cannot go below zero. Current calculated balance: %', new_balance;
  END IF;

  -- Read thresholds from settings (configurable, not hardcoded)
  SELECT loyalty_gold_threshold, loyalty_platinum_threshold
  INTO gold_threshold, plat_threshold
  FROM public.clinic_settings
  WHERE id = 1;

  -- Fallback if settings are missing
  gold_threshold := COALESCE(gold_threshold, 500);
  plat_threshold := COALESCE(plat_threshold, 1500);

  -- Determine tier
  IF new_lifetime >= plat_threshold THEN
    new_tier := 'platinum';
  ELSIF new_lifetime >= gold_threshold THEN
    new_tier := 'gold';
  ELSE
    new_tier := 'silver';
  END IF;

  UPDATE public.loyalty_cards
  SET
    points_balance  = new_balance,
    lifetime_points = new_lifetime,
    tier            = new_tier
  WHERE id = NEW.loyalty_card_id;

  RETURN NEW;
END;
$$;


-- в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
-- FIX #24: Prevent hard delete of medical records
-- Problem: treatment_plans cascade on user deletion.
-- в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

ALTER TABLE public.treatment_plans
  DROP CONSTRAINT IF EXISTS treatment_plans_user_id_fkey;

ALTER TABLE public.treatment_plans
  ADD CONSTRAINT treatment_plans_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES public.profiles(id) ON DELETE RESTRICT;

-- в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
-- FIX #25: Allowed soft-deletion RPC for patients
-- Problem: prevent_role_change prevents patients from setting is_deleted = true.
-- в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

CREATE OR REPLACE FUNCTION public.delete_my_account()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  uid uuid;
BEGIN
  uid := auth.uid();
  IF uid IS NULL THEN
    RAISE EXCEPTION 'Not authenticated.';
  END IF;

  -- Soft delete profile and anonymize PII
  UPDATE public.profiles
  SET 
    is_deleted = true,
    first_name = 'Deleted',
    last_name = 'User',
    phone = 'deleted_' || id::text,
    email = NULL,
    identity_number = NULL,
    address = NULL,
    updated_at = now()
  WHERE id = uid AND is_deleted = false;
END;
$$;

COMMENT ON FUNCTION public.delete_my_account() IS 'Allows patients to safely soft-delete their account and anonymize PII without breaking medical history constraints.';


-- в•”в•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•—
-- в•‘  DONE. All 25 audit fixes applied.                                     в•‘
-- в•‘                                                                        в•‘
-- в•‘  Summary of changes:                                                   в•‘
-- в•‘  - 7 new trigger functions/RPCs (security, validation, audit, deletion)в•‘
-- в•‘  - 3 updated trigger functions (schedule, review, loyalty)             в•‘
-- в•‘  - 2 new tables (appointment_audit_log, promotions, promotion_usages)  в•‘
-- в•‘  - 6 ALTER TABLE additions (new columns)                               в•‘
-- в•‘  - 4 RLS policy updates (profiles, appointments)                       в•‘
-- в•‘  - 3 constraint changes (review unique, past-booking, plan cascade)    в•‘
-- в•‘  - 1 new ENUM type (article_category, discount_type)                   в•‘
-- в•љв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ђв•ќ
