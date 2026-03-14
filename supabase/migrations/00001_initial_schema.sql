-- ============================================================================
-- SwiftDoc Clinic — Complete Supabase PostgreSQL Schema
-- Migration: 00001_initial_schema.sql
-- Generated: 2026-03-14
-- Architecture: v2 (3 Tech-Lead changes + 9 self-audit fixes)
-- ============================================================================
-- EXECUTION ORDER:
--   1. Extensions
--   2. Enums
--   3. Helper functions (SECURITY DEFINER)
--   4. Tables (dependency order)
--   5. Indexes
--   6. Row Level Security policies
--   7. Triggers & trigger functions
-- ============================================================================


-- ╔══════════════════════════════════════════════════════════════════════════╗
-- ║  1. EXTENSIONS                                                         ║
-- ╚══════════════════════════════════════════════════════════════════════════╝

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";      -- gen_random_uuid fallback
CREATE EXTENSION IF NOT EXISTS "pgcrypto";        -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "btree_gist";      -- for multicolumn gist exclude constraints


-- ╔══════════════════════════════════════════════════════════════════════════╗
-- ║  2. ENUMS                                                              ║
-- ╚══════════════════════════════════════════════════════════════════════════╝

CREATE TYPE public.appointment_status AS ENUM (
  'awaiting_payment',   -- slot locked, payment in progress (v2 addition)
  'pending',            -- payment received, awaiting clinic confirmation
  'confirmed',          -- clinic confirmed
  'in_progress',        -- patient is being seen
  'completed',          -- visit finished
  'cancelled',          -- cancelled by patient or system
  'rescheduled',        -- replaced by a new appointment
  'no_show'             -- patient did not arrive
);

CREATE TYPE public.payment_status AS ENUM (
  'pending',
  'paid',
  'failed',
  'refunded'
);

CREATE TYPE public.payment_method AS ENUM (
  'in_clinic',
  'card',
  'apple_pay',
  'google_pay'
);

CREATE TYPE public.loyalty_tier AS ENUM (
  'silver',
  'gold',
  'platinum'
);

CREATE TYPE public.loyalty_tx_type AS ENUM (
  'earn',
  'redeem',
  'adjust',
  'expire'
);

CREATE TYPE public.notification_type AS ENUM (
  'appointment_confirmation',
  'appointment_reminder',
  'treatment_reminder',
  'promotion',
  'clinic_update'
);

CREATE TYPE public.notification_channel AS ENUM (
  'push',
  'sms',
  'email'
);

CREATE TYPE public.user_role AS ENUM (
  'patient',
  'admin',
  'doctor'
);

CREATE TYPE public.language_pref AS ENUM (
  'ka',   -- Georgian
  'en',   -- English
  'ru'    -- Russian
);

CREATE TYPE public.family_relation AS ENUM (
  'child',
  'spouse',
  'parent',
  'sibling',
  'other'
);

CREATE TYPE public.treatment_status AS ENUM (
  'active',
  'paused',
  'completed',
  'cancelled'
);


-- ╔══════════════════════════════════════════════════════════════════════════╗
-- ║  3. HELPER FUNCTIONS (SECURITY DEFINER)                                ║
-- ║     Used by RLS policies — executed with elevated privileges            ║
-- ╚══════════════════════════════════════════════════════════════════════════╝

-- 3a. Check if current user is admin
CREATE OR REPLACE FUNCTION public.is_admin()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.profiles
    WHERE id = auth.uid()
      AND role = 'admin'
  );
$$;

-- 3b. Check if current user owns a given family member
CREATE OR REPLACE FUNCTION public.owns_family_member(fm_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.family_members
    WHERE id = fm_id
      AND owner_id = auth.uid()
  );
$$;

-- 3c. Check if current user is a doctor (has a linked doctor record)
CREATE OR REPLACE FUNCTION public.is_doctor()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.doctors
    WHERE profile_id = auth.uid()
      AND is_active = true
  );
$$;


-- ╔══════════════════════════════════════════════════════════════════════════╗
-- ║  4. TABLES (dependency order)                                          ║
-- ╚══════════════════════════════════════════════════════════════════════════╝

-- ────────────────────────────────────────────────────────────────
-- 4.1  profiles (extends auth.users)
-- ────────────────────────────────────────────────────────────────
CREATE TABLE public.profiles (
  id                    uuid        PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  phone                 text        NOT NULL,
  email                 text,
  first_name            text        NOT NULL,
  last_name             text        NOT NULL,
  date_of_birth         date,
  gender                text,
  identity_number       text,
  address               text,
  avatar_url            text,
  language              public.language_pref   NOT NULL DEFAULT 'ka',
  role                  public.user_role       NOT NULL DEFAULT 'patient',
  biometric_enabled     boolean     NOT NULL DEFAULT false,
  notifications_enabled boolean     NOT NULL DEFAULT true,
  is_deleted            boolean     NOT NULL DEFAULT false,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT profiles_phone_unique      UNIQUE (phone),
  CONSTRAINT profiles_email_unique      UNIQUE (email)
);

COMMENT ON TABLE public.profiles IS 'User profiles extending Supabase auth.users. Auto-created via trigger on signup.';

-- ────────────────────────────────────────────────────────────────
-- 4.2  family_members
-- ────────────────────────────────────────────────────────────────
CREATE TABLE public.family_members (
  id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id          uuid        NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  first_name        text        NOT NULL,
  last_name         text        NOT NULL,
  date_of_birth     date,
  identity_number   text,
  relation          public.family_relation NOT NULL DEFAULT 'child',
  avatar_url        text,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE public.family_members IS 'Family profiles managed by a primary account holder (owner_id).';

-- ────────────────────────────────────────────────────────────────
-- 4.3  doctors
-- ────────────────────────────────────────────────────────────────
CREATE TABLE public.doctors (
  id                uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
  profile_id        uuid          REFERENCES public.profiles(id) ON DELETE SET NULL,
  first_name        text          NOT NULL,
  last_name         text          NOT NULL,
  specialization    text          NOT NULL,
  bio               text,
  experience_years  int,
  languages         text[]        NOT NULL DEFAULT '{ka}',
  photo_url         text,
  is_active         boolean       NOT NULL DEFAULT true,
  avg_rating        numeric(2,1)  NOT NULL DEFAULT 0.0,
  review_count      int           NOT NULL DEFAULT 0,
  created_at        timestamptz   NOT NULL DEFAULT now()
);

COMMENT ON TABLE public.doctors IS 'Clinic doctors with cached rating. profile_id links to auth user if doctor has app access.';

-- ────────────────────────────────────────────────────────────────
-- 4.4  services
-- ────────────────────────────────────────────────────────────────
CREATE TABLE public.services (
  id                       uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
  name_ka                  text          NOT NULL,
  name_en                  text          NOT NULL,
  name_ru                  text          NOT NULL,
  description_ka           text,
  description_en           text,
  description_ru           text,
  price                    numeric(10,2) NOT NULL,
  duration_minutes         int           NOT NULL DEFAULT 30,
  is_recurring             boolean       NOT NULL DEFAULT false,
  recurring_interval_months int,
  is_active                boolean       NOT NULL DEFAULT true,
  sort_order               int           NOT NULL DEFAULT 0,
  created_at               timestamptz   NOT NULL DEFAULT now(),

  CONSTRAINT services_price_positive CHECK (price >= 0),
  CONSTRAINT services_duration_positive CHECK (duration_minutes > 0),
  CONSTRAINT services_recurring_check CHECK (
    (is_recurring = false) OR 
    (is_recurring = true AND recurring_interval_months IS NOT NULL AND recurring_interval_months > 0)
  )
);

COMMENT ON TABLE public.services IS 'Clinic services with multi-language names (ka/en/ru).';

-- ────────────────────────────────────────────────────────────────
-- 4.5  doctor_services (junction)
-- ────────────────────────────────────────────────────────────────
CREATE TABLE public.doctor_services (
  doctor_id   uuid NOT NULL REFERENCES public.doctors(id)   ON DELETE CASCADE,
  service_id  uuid NOT NULL REFERENCES public.services(id)  ON DELETE CASCADE,

  PRIMARY KEY (doctor_id, service_id)
);

COMMENT ON TABLE public.doctor_services IS 'Many-to-many: which doctors perform which services.';

-- ────────────────────────────────────────────────────────────────
-- 4.6  doctor_schedules
-- ────────────────────────────────────────────────────────────────
CREATE TABLE public.doctor_schedules (
  id            uuid    PRIMARY KEY DEFAULT gen_random_uuid(),
  doctor_id     uuid    NOT NULL REFERENCES public.doctors(id) ON DELETE CASCADE,
  day_of_week   int     NOT NULL,   -- 0 = Monday … 6 = Sunday
  start_time    time    NOT NULL,
  end_time      time    NOT NULL,
  is_active     boolean NOT NULL DEFAULT true,

  CONSTRAINT schedules_day_range   CHECK (day_of_week BETWEEN 0 AND 6),
  CONSTRAINT schedules_time_order  CHECK (end_time > start_time),
  CONSTRAINT schedules_unique_day  UNIQUE (doctor_id, day_of_week)   -- Audit fix #7
);

COMMENT ON TABLE public.doctor_schedules IS 'Weekly recurring schedule per doctor. One row per day.';

-- ────────────────────────────────────────────────────────────────
-- 4.6b  doctor_absences  ✨ NEW (v2 — Tech-Lead change #2)
-- ────────────────────────────────────────────────────────────────
CREATE TABLE public.doctor_absences (
  id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  doctor_id     uuid        NOT NULL REFERENCES public.doctors(id) ON DELETE CASCADE,
  start_date    date        NOT NULL,
  end_date      date        NOT NULL,
  reason        text,
  created_at    timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT absences_date_order CHECK (end_date >= start_date)
);

COMMENT ON TABLE public.doctor_absences IS 'Doctor vacations, sick leaves, and other absences. Booking logic must check this table.';

-- ────────────────────────────────────────────────────────────────
-- 4.7  appointments
-- ────────────────────────────────────────────────────────────────
CREATE TABLE public.appointments (
  id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id             uuid                 REFERENCES public.profiles(id)         ON DELETE SET NULL,
  family_member_id    uuid                 REFERENCES public.family_members(id)   ON DELETE SET NULL,
  doctor_id           uuid        NOT NULL REFERENCES public.doctors(id)          ON DELETE RESTRICT,
  service_id          uuid        NOT NULL REFERENCES public.services(id)         ON DELETE RESTRICT,
  scheduled_at        timestamptz NOT NULL,
  price_at_booking    numeric(10,2),
  duration_minutes    int         NOT NULL DEFAULT 30,
  status              public.appointment_status NOT NULL DEFAULT 'awaiting_payment',
  locked_until        timestamptz,           -- ✨ v2: slot lock TTL (15 min)
  notes               text,
  rescheduled_from    uuid                 REFERENCES public.appointments(id)     ON DELETE SET NULL,
  cancelled_at        timestamptz,
  cancellation_reason text,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT appointments_duration_positive CHECK (duration_minutes > 0),
  CONSTRAINT appointments_no_past_booking   CHECK (scheduled_at > created_at)
);

COMMENT ON TABLE public.appointments IS 'Patient appointments. status starts as awaiting_payment with a locked_until TTL for slot concurrency.';
COMMENT ON COLUMN public.appointments.locked_until IS 'Slot reserved until this time during payment. NULL after confirmation or expiry.';
COMMENT ON COLUMN public.appointments.family_member_id IS 'NULL = appointment is for the user themselves; non-null = for a managed family member.';

-- ────────────────────────────────────────────────────────────────
-- 4.8  payments
-- ────────────────────────────────────────────────────────────────
CREATE TABLE public.payments (
  id               uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
  appointment_id   uuid          NOT NULL REFERENCES public.appointments(id) ON DELETE CASCADE,
  user_id          uuid                   REFERENCES public.profiles(id)      ON DELETE SET NULL,
  amount           numeric(10,2) NOT NULL,
  method           public.payment_method,     -- nullable: set on confirmation (Audit fix #6)
  status           public.payment_status NOT NULL DEFAULT 'pending',
  transaction_ref  text,
  paid_at          timestamptz,
  created_at       timestamptz   NOT NULL DEFAULT now(),

  CONSTRAINT payments_amount_positive  CHECK (amount >= 0),
  CONSTRAINT payments_unique_appt     UNIQUE (appointment_id)
);

COMMENT ON TABLE public.payments IS 'One payment per appointment. method is nullable until payment is confirmed (e.g. in_clinic decided later).';

-- ────────────────────────────────────────────────────────────────
-- 4.9  loyalty_cards
-- ────────────────────────────────────────────────────────────────
CREATE TABLE public.loyalty_cards (
  id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id           uuid        NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  tier              public.loyalty_tier NOT NULL DEFAULT 'silver',
  points_balance    int         NOT NULL DEFAULT 0,
  lifetime_points   int         NOT NULL DEFAULT 0,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT loyalty_unique_user       UNIQUE (user_id),
  CONSTRAINT loyalty_balance_non_neg   CHECK (points_balance >= 0),           -- Audit fix #4
  CONSTRAINT loyalty_lifetime_non_neg  CHECK (lifetime_points >= 0)
);

COMMENT ON TABLE public.loyalty_cards IS 'One loyalty card per patient. Tier auto-promoted by trigger on lifetime_points thresholds.';

-- ────────────────────────────────────────────────────────────────
-- 4.10  loyalty_transactions
-- ────────────────────────────────────────────────────────────────
CREATE TABLE public.loyalty_transactions (
  id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  loyalty_card_id  uuid        NOT NULL REFERENCES public.loyalty_cards(id) ON DELETE CASCADE,
  type             public.loyalty_tx_type NOT NULL,
  points           int         NOT NULL,  -- positive for earn, negative for redeem
  description      text,
  appointment_id   uuid        REFERENCES public.appointments(id) ON DELETE SET NULL,
  created_at       timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE public.loyalty_transactions IS 'Immutable ledger of point changes. Trigger recalculates loyalty_cards on INSERT.';

-- ────────────────────────────────────────────────────────────────
-- 4.11  treatment_plans
-- ────────────────────────────────────────────────────────────────
CREATE TABLE public.treatment_plans (
  id                       uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id                  uuid        NOT NULL REFERENCES public.profiles(id)        ON DELETE CASCADE,
  family_member_id         uuid                 REFERENCES public.family_members(id)   ON DELETE SET NULL,
  doctor_id                uuid        NOT NULL REFERENCES public.doctors(id)          ON DELETE RESTRICT,
  service_id               uuid                 REFERENCES public.services(id)         ON DELETE SET NULL,
  title                    text        NOT NULL,
  description              text,
  status                   public.treatment_status NOT NULL DEFAULT 'active',
  start_date               date        NOT NULL,
  end_date                 date,
  total_duration_months    int,
  next_reminder_at         timestamptz,
  reminder_interval_months int,
  created_at               timestamptz NOT NULL DEFAULT now(),
  updated_at               timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT tp_date_order CHECK (end_date IS NULL OR end_date >= start_date),
  CONSTRAINT tp_duration_positive CHECK (total_duration_months IS NULL OR total_duration_months > 0),
  CONSTRAINT tp_reminder_interval_positive CHECK (reminder_interval_months IS NULL OR reminder_interval_months > 0)
);

COMMENT ON TABLE public.treatment_plans IS 'Doctor-assigned treatment plans with smart reminder scheduling via pg_cron.';

-- ────────────────────────────────────────────────────────────────
-- 4.12  doctor_reviews
-- ────────────────────────────────────────────────────────────────
CREATE TABLE public.doctor_reviews (
  id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  doctor_id       uuid        NOT NULL REFERENCES public.doctors(id)       ON DELETE CASCADE,
  user_id         uuid        NOT NULL REFERENCES public.profiles(id)      ON DELETE CASCADE,
  appointment_id  uuid        NOT NULL REFERENCES public.appointments(id)  ON DELETE CASCADE, -- Audit fix #5: required
  rating          int         NOT NULL,
  comment         text,
  created_at      timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT reviews_rating_range      CHECK (rating BETWEEN 1 AND 5),
  CONSTRAINT reviews_unique_per_doctor UNIQUE (user_id, doctor_id)         -- Audit fix #5: one review per doctor per user
);

COMMENT ON TABLE public.doctor_reviews IS 'Patient reviews of doctors. One review per (user, doctor) pair. Appointment required.';

-- ────────────────────────────────────────────────────────────────
-- 4.13  news_articles
-- ────────────────────────────────────────────────────────────────
CREATE TABLE public.news_articles (
  id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  author_id        uuid        NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  title_ka         text        NOT NULL,
  title_en         text        NOT NULL,
  title_ru         text        NOT NULL,
  body_ka          text        NOT NULL,
  body_en          text        NOT NULL,
  body_ru          text        NOT NULL,
  cover_image_url  text,
  is_promotion     boolean     NOT NULL DEFAULT false,
  is_published     boolean     NOT NULL DEFAULT false,
  published_at     timestamptz,
  created_at       timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE public.news_articles IS 'Clinic news, tips, and promotions with multi-language content.';

-- ────────────────────────────────────────────────────────────────
-- 4.14  notifications
-- ────────────────────────────────────────────────────────────────
CREATE TABLE public.notifications (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid        NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  type        public.notification_type    NOT NULL,
  channel     public.notification_channel NOT NULL,
  title       text        NOT NULL,
  body        text        NOT NULL,
  data        jsonb,
  is_read     boolean     NOT NULL DEFAULT false,
  sent_at     timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE public.notifications IS 'Push/SMS/email notification records. Inserted by Edge Functions and pg_cron.';

-- ────────────────────────────────────────────────────────────────
-- 4.15  user_devices
-- ────────────────────────────────────────────────────────────────
CREATE TABLE public.user_devices (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid        NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  fcm_token   text        NOT NULL,
  platform    text        NOT NULL,   -- 'ios' | 'android'
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT devices_unique_token UNIQUE (fcm_token),
  CONSTRAINT devices_platform_check CHECK (platform IN ('ios', 'android'))
);

COMMENT ON TABLE public.user_devices IS 'FCM push notification tokens per device.';

-- ────────────────────────────────────────────────────────────────
-- 4.16  clinic_settings  ✨ NEW (v2 — Tech-Lead change #3)
-- ────────────────────────────────────────────────────────────────
CREATE TABLE public.clinic_settings (
  id              int           PRIMARY KEY DEFAULT 1,
  name            text          NOT NULL,
  address         text          NOT NULL,
  phone           text          NOT NULL,
  email           text,
  working_hours   jsonb         NOT NULL DEFAULT '{}',
  map_url         text,
  updated_at      timestamptz   NOT NULL DEFAULT now(),

  CONSTRAINT clinic_singleton CHECK (id = 1)
);

COMMENT ON TABLE public.clinic_settings IS 'Singleton table (id=1 always). Stores global clinic contact info and working hours.';

-- Seed the singleton row so it always exists
INSERT INTO public.clinic_settings (id, name, address, phone, working_hours)
VALUES (1, 'SwiftDoc Clinic', 'Tbilisi, Georgia', '+995 XXX XXX XXX', '{"mon":"09:00-18:00","tue":"09:00-18:00","wed":"09:00-18:00","thu":"09:00-18:00","fri":"09:00-18:00","sat":"10:00-15:00","sun":"closed"}');


-- ╔══════════════════════════════════════════════════════════════════════════╗
-- ║  5. INDEXES                                                            ║
-- ╚══════════════════════════════════════════════════════════════════════════╝

-- profiles
CREATE INDEX idx_profiles_role ON public.profiles(role);

-- family_members
CREATE INDEX idx_family_members_owner ON public.family_members(owner_id);

-- doctors
CREATE INDEX idx_doctors_active         ON public.doctors(is_active);
CREATE INDEX idx_doctors_specialization ON public.doctors(specialization);

-- doctor_absences
CREATE INDEX idx_doctor_absences_doctor     ON public.doctor_absences(doctor_id);
CREATE INDEX idx_doctor_absences_dates      ON public.doctor_absences(start_date, end_date);

-- appointments
CREATE INDEX idx_appointments_user          ON public.appointments(user_id);
CREATE INDEX idx_appointments_doctor        ON public.appointments(doctor_id);
CREATE INDEX idx_appointments_schedule      ON public.appointments(scheduled_at, status);
CREATE INDEX idx_appointments_locked_until  ON public.appointments(locked_until) WHERE locked_until IS NOT NULL;

-- ✨ CRITICAL: prevents double-booking the same doctor at the same time
-- Uses EXCLUDE constraint with tstzrange to prevent overlapping times (Audit fix #1.1)
ALTER TABLE public.appointments ADD CONSTRAINT no_overlapping_appointments 
  EXCLUDE USING gist (
    doctor_id WITH =, 
    tstzrange(scheduled_at, scheduled_at + (duration_minutes || ' minutes')::interval) WITH &&
  ) WHERE (status NOT IN ('cancelled', 'rescheduled'));

-- payments
CREATE INDEX idx_payments_user ON public.payments(user_id);
-- unique on appointment_id already created via CONSTRAINT

-- loyalty_transactions
CREATE INDEX idx_loyalty_tx_card ON public.loyalty_transactions(loyalty_card_id);

-- treatment_plans
CREATE INDEX idx_treatment_plans_user_status   ON public.treatment_plans(user_id, status);
CREATE INDEX idx_treatment_plans_next_reminder ON public.treatment_plans(next_reminder_at) WHERE next_reminder_at IS NOT NULL;

-- doctor_reviews
CREATE INDEX idx_doctor_reviews_doctor ON public.doctor_reviews(doctor_id);

-- notifications
CREATE INDEX idx_notifications_user_read ON public.notifications(user_id, is_read);

-- news_articles
CREATE INDEX idx_news_published ON public.news_articles(is_published, published_at DESC);


-- ╔══════════════════════════════════════════════════════════════════════════╗
-- ║  6. ROW LEVEL SECURITY (RLS)                                           ║
-- ║     Every table MUST have RLS enabled. No exceptions.                  ║
-- ╚══════════════════════════════════════════════════════════════════════════╝

-- ── Enable RLS on ALL tables ──────────────────────────────────────────────

ALTER TABLE public.profiles            ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.family_members      ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.doctors             ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.services            ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.doctor_services     ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.doctor_schedules    ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.doctor_absences     ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.appointments        ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.payments            ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.loyalty_cards       ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.loyalty_transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.treatment_plans     ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.doctor_reviews      ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.news_articles       ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.notifications       ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_devices        ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.clinic_settings     ENABLE ROW LEVEL SECURITY;


-- ── 6.1  profiles ─────────────────────────────────────────────────────────

CREATE POLICY "profiles_select_own" ON public.profiles
  FOR SELECT USING (auth.uid() = id);

CREATE POLICY "profiles_update_own" ON public.profiles
  FOR UPDATE USING (auth.uid() = id)
  WITH CHECK (auth.uid() = id);

CREATE POLICY "profiles_admin_select" ON public.profiles
  FOR SELECT USING (public.is_admin());


-- ── 6.2  family_members ───────────────────────────────────────────────────

CREATE POLICY "family_select_own" ON public.family_members
  FOR SELECT USING (owner_id = auth.uid());

CREATE POLICY "family_insert_own" ON public.family_members
  FOR INSERT WITH CHECK (owner_id = auth.uid());

CREATE POLICY "family_update_own" ON public.family_members
  FOR UPDATE USING (owner_id = auth.uid())
  WITH CHECK (owner_id = auth.uid());

CREATE POLICY "family_delete_own" ON public.family_members
  FOR DELETE USING (owner_id = auth.uid());

CREATE POLICY "family_admin_all" ON public.family_members
  FOR ALL USING (public.is_admin());


-- ── 6.3  doctors (public read, admin write) ───────────────────────────────

CREATE POLICY "doctors_select_authenticated" ON public.doctors
  FOR SELECT USING (auth.role() = 'authenticated');

CREATE POLICY "doctors_admin_insert" ON public.doctors
  FOR INSERT WITH CHECK (public.is_admin());

CREATE POLICY "doctors_admin_update" ON public.doctors
  FOR UPDATE USING (public.is_admin())
  WITH CHECK (public.is_admin());

CREATE POLICY "doctors_admin_delete" ON public.doctors
  FOR DELETE USING (public.is_admin());


-- ── 6.4  services (public read, admin write) ─────────────────────────────

CREATE POLICY "services_select_authenticated" ON public.services
  FOR SELECT USING (auth.role() = 'authenticated');

CREATE POLICY "services_admin_insert" ON public.services
  FOR INSERT WITH CHECK (public.is_admin());

CREATE POLICY "services_admin_update" ON public.services
  FOR UPDATE USING (public.is_admin())
  WITH CHECK (public.is_admin());

CREATE POLICY "services_admin_delete" ON public.services
  FOR DELETE USING (public.is_admin());


-- ── 6.5  doctor_services (public read, admin write) ──────────────────────

CREATE POLICY "doctor_services_select_authenticated" ON public.doctor_services
  FOR SELECT USING (auth.role() = 'authenticated');

CREATE POLICY "doctor_services_admin_insert" ON public.doctor_services
  FOR INSERT WITH CHECK (public.is_admin());

CREATE POLICY "doctor_services_admin_delete" ON public.doctor_services
  FOR DELETE USING (public.is_admin());


-- ── 6.6  doctor_schedules (public read, admin write) ─────────────────────

CREATE POLICY "schedules_select_authenticated" ON public.doctor_schedules
  FOR SELECT USING (auth.role() = 'authenticated');

CREATE POLICY "schedules_admin_insert" ON public.doctor_schedules
  FOR INSERT WITH CHECK (public.is_admin());

CREATE POLICY "schedules_admin_update" ON public.doctor_schedules
  FOR UPDATE USING (public.is_admin())
  WITH CHECK (public.is_admin());

CREATE POLICY "schedules_admin_delete" ON public.doctor_schedules
  FOR DELETE USING (public.is_admin());


-- ── 6.6b  doctor_absences (public read, admin write) ─────────────────────

CREATE POLICY "absences_select_authenticated" ON public.doctor_absences
  FOR SELECT USING (auth.role() = 'authenticated');

CREATE POLICY "absences_admin_insert" ON public.doctor_absences
  FOR INSERT WITH CHECK (public.is_admin());

CREATE POLICY "absences_admin_update" ON public.doctor_absences
  FOR UPDATE USING (public.is_admin())
  WITH CHECK (public.is_admin());

CREATE POLICY "absences_admin_delete" ON public.doctor_absences
  FOR DELETE USING (public.is_admin());


-- ── 6.7  appointments ────────────────────────────────────────────────────

CREATE POLICY "appointments_select_own" ON public.appointments
  FOR SELECT USING (user_id = auth.uid());

CREATE POLICY "appointments_insert_own" ON public.appointments
  FOR INSERT WITH CHECK (
    user_id = auth.uid()
    AND (
      family_member_id IS NULL
      OR public.owns_family_member(family_member_id)
    )
  );

CREATE POLICY "appointments_update_own" ON public.appointments
  FOR UPDATE USING (user_id = auth.uid())
  WITH CHECK (user_id = auth.uid());

CREATE POLICY "appointments_admin_all" ON public.appointments
  FOR ALL USING (public.is_admin());

-- Doctors can SELECT appointments assigned to them
CREATE POLICY "appointments_doctor_select" ON public.appointments
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM public.doctors
      WHERE doctors.id = appointments.doctor_id
        AND doctors.profile_id = auth.uid()
    )
  );


-- ── 6.8  payments ─────────────────────────────────────────────────────────

CREATE POLICY "payments_select_own" ON public.payments
  FOR SELECT USING (user_id = auth.uid());

CREATE POLICY "payments_admin_all" ON public.payments
  FOR ALL USING (public.is_admin());


-- ── 6.9  loyalty_cards ───────────────────────────────────────────────────

CREATE POLICY "loyalty_cards_select_own" ON public.loyalty_cards
  FOR SELECT USING (user_id = auth.uid());

CREATE POLICY "loyalty_cards_admin_all" ON public.loyalty_cards
  FOR ALL USING (public.is_admin());


-- ── 6.10  loyalty_transactions ───────────────────────────────────────────

CREATE POLICY "loyalty_tx_select_own" ON public.loyalty_transactions
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM public.loyalty_cards
      WHERE loyalty_cards.id = loyalty_transactions.loyalty_card_id
        AND loyalty_cards.user_id = auth.uid()
    )
  );

CREATE POLICY "loyalty_tx_admin_insert" ON public.loyalty_transactions
  FOR INSERT WITH CHECK (public.is_admin());

CREATE POLICY "loyalty_tx_admin_all" ON public.loyalty_transactions
  FOR ALL USING (public.is_admin());


-- ── 6.11  treatment_plans ────────────────────────────────────────────────

CREATE POLICY "treatment_plans_select_own" ON public.treatment_plans
  FOR SELECT USING (user_id = auth.uid());

CREATE POLICY "treatment_plans_admin_all" ON public.treatment_plans
  FOR ALL USING (public.is_admin());

-- Doctors can manage treatment plans they're assigned to
CREATE POLICY "treatment_plans_doctor_all" ON public.treatment_plans
  FOR ALL USING (
    EXISTS (
      SELECT 1 FROM public.doctors
      WHERE doctors.id = treatment_plans.doctor_id
        AND doctors.profile_id = auth.uid()
    )
  );


-- ── 6.12  doctor_reviews ─────────────────────────────────────────────────

CREATE POLICY "reviews_select_authenticated" ON public.doctor_reviews
  FOR SELECT USING (auth.role() = 'authenticated');

CREATE POLICY "reviews_insert_own" ON public.doctor_reviews
  FOR INSERT WITH CHECK (user_id = auth.uid());

CREATE POLICY "reviews_update_own" ON public.doctor_reviews
  FOR UPDATE USING (user_id = auth.uid())
  WITH CHECK (user_id = auth.uid());

CREATE POLICY "reviews_admin_delete" ON public.doctor_reviews
  FOR DELETE USING (public.is_admin());


-- ── 6.13  news_articles ──────────────────────────────────────────────────

CREATE POLICY "news_select_published" ON public.news_articles
  FOR SELECT USING (is_published = true);

CREATE POLICY "news_admin_all" ON public.news_articles
  FOR ALL USING (public.is_admin());


-- ── 6.14  notifications ──────────────────────────────────────────────────

CREATE POLICY "notifications_select_own" ON public.notifications
  FOR SELECT USING (user_id = auth.uid());

CREATE POLICY "notifications_update_own" ON public.notifications
  FOR UPDATE USING (user_id = auth.uid())
  WITH CHECK (user_id = auth.uid());

-- Service-role can insert (Edge Functions, pg_cron)  — Audit fix #9
-- Note: service_role bypasses RLS by default in Supabase, so this is
-- documented here for clarity. No explicit policy needed for service_role.


-- ── 6.15  user_devices ───────────────────────────────────────────────────

CREATE POLICY "devices_select_own" ON public.user_devices
  FOR SELECT USING (user_id = auth.uid());

CREATE POLICY "devices_insert_own" ON public.user_devices
  FOR INSERT WITH CHECK (user_id = auth.uid());

CREATE POLICY "devices_update_own" ON public.user_devices   -- Audit fix #8
  FOR UPDATE USING (user_id = auth.uid())
  WITH CHECK (user_id = auth.uid());

CREATE POLICY "devices_delete_own" ON public.user_devices
  FOR DELETE USING (user_id = auth.uid());


-- ── 6.16  clinic_settings ────────────────────────────────────────────────

CREATE POLICY "clinic_settings_select_authenticated" ON public.clinic_settings
  FOR SELECT USING (auth.role() = 'authenticated');

CREATE POLICY "clinic_settings_admin_update" ON public.clinic_settings
  FOR UPDATE USING (public.is_admin())
  WITH CHECK (public.is_admin());


-- ╔══════════════════════════════════════════════════════════════════════════╗
-- ║  7. TRIGGER FUNCTIONS & TRIGGERS                                       ║
-- ╚══════════════════════════════════════════════════════════════════════════╝

-- ── 7.1  handle_new_user — auto-create profile on signup ──────────────────

CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  INSERT INTO public.profiles (id, phone, first_name, last_name, email)
  VALUES (
    NEW.id,
    COALESCE(NEW.phone, ''),
    COALESCE(NEW.raw_user_meta_data->>'first_name', ''),
    COALESCE(NEW.raw_user_meta_data->>'last_name', ''),
    NEW.email
  );
  RETURN NEW;
END;
$$;

CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();


-- ── 7.2  auto_create_loyalty_card — every new patient gets a card ─────────

CREATE OR REPLACE FUNCTION public.auto_create_loyalty_card()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF NEW.role = 'patient' THEN
    INSERT INTO public.loyalty_cards (user_id)
    VALUES (NEW.id)
    ON CONFLICT (user_id) DO NOTHING;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER on_profile_created_loyalty
  AFTER INSERT ON public.profiles
  FOR EACH ROW EXECUTE FUNCTION public.auto_create_loyalty_card();


-- ── 7.3  set_updated_at — generic reusable trigger ────────────────────────

CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

-- Apply to all tables with updated_at
CREATE TRIGGER trg_profiles_updated_at
  BEFORE UPDATE ON public.profiles
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

CREATE TRIGGER trg_family_members_updated_at
  BEFORE UPDATE ON public.family_members
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

CREATE TRIGGER trg_appointments_updated_at
  BEFORE UPDATE ON public.appointments
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

CREATE TRIGGER trg_loyalty_cards_updated_at
  BEFORE UPDATE ON public.loyalty_cards
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

CREATE TRIGGER trg_treatment_plans_updated_at
  BEFORE UPDATE ON public.treatment_plans
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

CREATE TRIGGER trg_user_devices_updated_at
  BEFORE UPDATE ON public.user_devices
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

CREATE TRIGGER trg_clinic_settings_updated_at
  BEFORE UPDATE ON public.clinic_settings
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


-- ── 7.4  recalc_doctor_rating — update cached avg on review changes ──────

CREATE OR REPLACE FUNCTION public.recalc_doctor_rating()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  target_doctor_id uuid;
BEGIN
  -- Determine which doctor to recalculate
  IF TG_OP = 'DELETE' THEN
    target_doctor_id := OLD.doctor_id;
  ELSE
    target_doctor_id := NEW.doctor_id;
  END IF;

  UPDATE public.doctors
  SET
    avg_rating   = COALESCE((
      SELECT ROUND(AVG(rating)::numeric, 1)
      FROM public.doctor_reviews
      WHERE doctor_id = target_doctor_id
    ), 0.0),
    review_count = (
      SELECT COUNT(*)
      FROM public.doctor_reviews
      WHERE doctor_id = target_doctor_id
    )
  WHERE id = target_doctor_id;

  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_recalc_doctor_rating
  AFTER INSERT OR UPDATE OR DELETE ON public.doctor_reviews
  FOR EACH ROW EXECUTE FUNCTION public.recalc_doctor_rating();


-- ── 7.5  recalc_loyalty — update card balance, lifetime, and tier ────────

CREATE OR REPLACE FUNCTION public.recalc_loyalty()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  new_balance   int;
  new_lifetime  int;
  new_tier      public.loyalty_tier;
BEGIN
  -- Recalculate totals from the full ledger (authoritative source of truth)
  SELECT
    COALESCE(SUM(points), 0),
    COALESCE(SUM(CASE WHEN points > 0 THEN points ELSE 0 END), 0)
  INTO new_balance, new_lifetime
  FROM public.loyalty_transactions
  WHERE loyalty_card_id = NEW.loyalty_card_id;

  -- Guard: prevent negative balance (Audit fix #4)
  IF new_balance < 0 THEN
    RAISE EXCEPTION 'Loyalty points balance cannot go below zero. Current calculated balance: %', new_balance;
  END IF;

  -- Determine tier from lifetime points
  IF new_lifetime >= 1500 THEN
    new_tier := 'platinum';
  ELSIF new_lifetime >= 500 THEN
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

CREATE TRIGGER trg_recalc_loyalty
  AFTER INSERT ON public.loyalty_transactions
  FOR EACH ROW EXECUTE FUNCTION public.recalc_loyalty();


-- ── 7.6  enforce_cancellation_window — 12-hour rule ─────────────────────

CREATE OR REPLACE FUNCTION public.enforce_cancellation_window()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  -- Admins bypass restrictions
  IF public.is_admin() THEN
    IF NEW.status = 'cancelled' AND OLD.status <> 'cancelled' THEN
      NEW.cancelled_at := now();
    END IF;
    RETURN NEW;
  END IF;

  -- Allow system (pg_cron) or user to cancel 'awaiting_payment' prior to confirmation (Audit fix #1.2)
  IF NEW.status = 'cancelled' AND OLD.status = 'awaiting_payment' THEN
    NEW.cancelled_at := now();
    IF NEW.cancellation_reason IS NULL THEN
      NEW.cancellation_reason := 'Cancelled before payment confirmation';
    END IF;
    RETURN NEW;
  END IF;

  -- Enforce 12-hour rule for canceling a confirmed/pending appointment
  IF NEW.status = 'cancelled' AND OLD.status <> 'cancelled' THEN
    IF OLD.scheduled_at - now() < interval '12 hours' THEN
      RAISE EXCEPTION 'Cannot cancel appointment less than 12 hours before the scheduled time. Appointment: %, Scheduled: %',
        NEW.id, OLD.scheduled_at;
    END IF;
    NEW.cancelled_at := now();
  END IF;

  -- Enforce 12-hour rule for rescheduling (Audit fix #2.1)
  IF (NEW.status = 'rescheduled' AND OLD.status <> 'rescheduled') OR (NEW.scheduled_at <> OLD.scheduled_at) THEN
    IF OLD.scheduled_at - now() < interval '12 hours' THEN
      RAISE EXCEPTION 'Cannot reschedule appointment less than 12 hours before the scheduled time.';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_enforce_cancellation_window
  BEFORE UPDATE ON public.appointments
  FOR EACH ROW EXECUTE FUNCTION public.enforce_cancellation_window();


-- ── 7.7  schedule_recurring_reminder — auto-schedule follow-ups ─────────

CREATE OR REPLACE FUNCTION public.schedule_recurring_reminder()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  svc_is_recurring boolean;
  svc_interval int;
  svc_name_en text;
BEGIN
  -- Check if status changed to completed
  IF NEW.status = 'completed' AND (OLD.status IS DISTINCT FROM 'completed') THEN
    -- If user_id is null (e.g. softly deleted user), don't schedule
    IF NEW.user_id IS NULL THEN
      RETURN NEW;
    END IF;

    -- Get service info
    SELECT is_recurring, recurring_interval_months, name_en
    INTO svc_is_recurring, svc_interval, svc_name_en
    FROM public.services
    WHERE id = NEW.service_id;

    IF svc_is_recurring AND svc_interval IS NOT NULL THEN
      -- Audit fix #2.3: Prevent spamming treatment plans
      IF EXISTS (
        SELECT 1 FROM public.treatment_plans
        WHERE user_id = NEW.user_id
          AND (family_member_id = NEW.family_member_id OR (family_member_id IS NULL AND NEW.family_member_id IS NULL))
          AND service_id = NEW.service_id
          AND status = 'active'
      ) THEN
        UPDATE public.treatment_plans
        SET next_reminder_at = now() + (svc_interval || ' months')::interval,
            updated_at = now()
        WHERE user_id = NEW.user_id
          AND (family_member_id = NEW.family_member_id OR (family_member_id IS NULL AND NEW.family_member_id IS NULL))
          AND service_id = NEW.service_id
          AND status = 'active';
      ELSE
        -- Create a new treatment plan with the reminder
        INSERT INTO public.treatment_plans (
          user_id,
          family_member_id,
          doctor_id,
          service_id,
          title,
          description,
          status,
          start_date,
          next_reminder_at,
          reminder_interval_months
        ) VALUES (
          NEW.user_id,
          NEW.family_member_id,
          NEW.doctor_id,
          NEW.service_id,
          'Regular ' || svc_name_en,
          'Automatically created recurring treatment plan after completed visit.',
          'active',
          CURRENT_DATE,
          now() + (svc_interval || ' months')::interval,
          svc_interval
        );
      END IF;
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_schedule_recurring_reminder
  AFTER UPDATE ON public.appointments
  FOR EACH ROW EXECUTE FUNCTION public.schedule_recurring_reminder();


-- ── 7.8  expire_payment_locks — pg_cron sweeps stale locks ──────────────
--    This function is designed to be called by pg_cron every 5 minutes:
--    SELECT cron.schedule('expire-payment-locks', '*/5 * * * *',
--      $$SELECT public.expire_payment_locks()$$
--    );

CREATE OR REPLACE FUNCTION public.expire_payment_locks()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  UPDATE public.appointments
  SET
    status       = 'cancelled',
    cancelled_at = now(),
    cancellation_reason = 'Payment lock expired (15-min timeout)'
  WHERE status = 'awaiting_payment'
    AND locked_until IS NOT NULL
    AND locked_until < now();
END;
$$;


-- ── 7.9  validate_doctor_review — prevent fake reviews (Audit fix #2.2) ──
CREATE OR REPLACE FUNCTION public.validate_doctor_review()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  appt_record record;
BEGIN
  SELECT * INTO appt_record
  FROM public.appointments
  WHERE id = NEW.appointment_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Appointment not found.';
  END IF;

  IF appt_record.user_id <> NEW.user_id THEN
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

CREATE TRIGGER trg_validate_doctor_review
  BEFORE INSERT OR UPDATE ON public.doctor_reviews
  FOR EACH ROW EXECUTE FUNCTION public.validate_doctor_review();


-- ── 7.10 prevent_loyalty_tampering — append-only ledger (Audit fix #3.2) ─
CREATE OR REPLACE FUNCTION public.prevent_loyalty_tampering()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  RAISE EXCEPTION 'Loyalty transactions are immutable. Insert an adjustment transaction instead.';
END;
$$;

CREATE TRIGGER trg_loyalty_tx_immutable
  BEFORE UPDATE OR DELETE ON public.loyalty_transactions
  FOR EACH ROW EXECUTE FUNCTION public.prevent_loyalty_tampering();


-- ── 7.11 validate_appointment_schedule — enforce absences (Audit fix #3.1)
CREATE OR REPLACE FUNCTION public.validate_appointment_schedule()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  appt_date date;
BEGIN
  -- We only check if scheduling a new appointment or changing the time/doctor
  IF TG_OP = 'INSERT' OR (TG_OP = 'UPDATE' AND (NEW.scheduled_at <> OLD.scheduled_at OR NEW.doctor_id <> OLD.doctor_id)) THEN
    IF NEW.status IN ('cancelled', 'rescheduled') THEN
      RETURN NEW;
    END IF;

    appt_date := NEW.scheduled_at::date;
    
    -- Check absences
    IF EXISTS (
      SELECT 1 FROM public.doctor_absences
      WHERE doctor_id = NEW.doctor_id
        AND appt_date >= start_date 
        AND appt_date <= end_date
    ) THEN
      RAISE EXCEPTION 'Doctor is absent on this date.';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_appointment_schedule
  BEFORE INSERT OR UPDATE ON public.appointments
  FOR EACH ROW EXECUTE FUNCTION public.validate_appointment_schedule();


-- ╔══════════════════════════════════════════════════════════════════════════╗
-- ║  8. STORAGE BUCKETS (Supabase Storage)                                 ║
-- ║     Run these via Supabase Dashboard > Storage or via supabase CLI.     ║
-- ║     Included here as reference SQL.                                    ║
-- ╚══════════════════════════════════════════════════════════════════════════╝

-- Note: Supabase storage bucket creation is typically done via the
-- dashboard or supabase CLI. The SQL below documents the intended config.

-- INSERT INTO storage.buckets (id, name, public) VALUES
--   ('avatars',       'avatars',       false),
--   ('doctor-photos', 'doctor-photos', true),
--   ('news-images',   'news-images',   true);

-- Storage RLS policies (apply via dashboard):
-- avatars:       owner can read/write own files (path: {user_id}/*)
-- doctor-photos: public read, admin write
-- news-images:   public read, admin write


-- ╔══════════════════════════════════════════════════════════════════════════╗
-- ║  DONE. Schema ready for Supabase SQL Editor.                           ║
-- ║                                                                        ║
-- ║  Post-migration checklist:                                             ║
-- ║  1. Enable pg_cron extension in Supabase Dashboard > Database          ║
-- ║  2. Schedule: SELECT cron.schedule('expire-payment-locks',             ║
-- ║     '*/5 * * * *', $$SELECT public.expire_payment_locks()$$);          ║
-- ║  3. Create storage buckets via Dashboard                               ║
-- ║  4. Configure Supabase Auth for Phone OTP provider                     ║
-- ╚══════════════════════════════════════════════════════════════════════════╝
