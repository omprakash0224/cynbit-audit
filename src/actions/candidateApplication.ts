'use server';

import { headers } from 'next/headers';
import {
  CandidateApplicationSchema,
  type CandidateApplicationInput,
} from '@/lib/validations/candidateSchema';

/**
 * Re-Architected Server Action: submitCandidateApplication
 * 
 * Key Architectural & Security Enhancements:
 * 1. Server-Side Schema Validation with Zod (mitigates parameter tampering).
 * 2. Rate Limiting via Client IP & Hash Bucket (mitigates denial-of-wallet / spam).
 * 3. Privacy-Preserving Duplicate Handling (prevents user enumeration & unauthorized trackingUrl exposure).
 * 4. Asynchronous Queue Decoupling (prevents serverless function timeouts on downstream DB/email services).
 */

interface ServerActionResponse {
  success: boolean;
  message?: string;
  error?: string;
  fieldErrors?: Record<string, string[]>;
}

// Simulated fast in-memory rate limiter (in production: Upstash Redis / Vercel KV)
const submissionRateLimitMap = new Map<string, { count: number; firstSeen: number }>();
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const MAX_SUBMISSIONS_PER_WINDOW = 3;

function isRateLimited(identifier: string): boolean {
  const now = Date.now();
  const record = submissionRateLimitMap.get(identifier);

  if (!record || now - record.firstSeen > RATE_LIMIT_WINDOW_MS) {
    submissionRateLimitMap.set(identifier, { count: 1, firstSeen: now });
    return false;
  }

  if (record.count >= MAX_SUBMISSIONS_PER_WINDOW) {
    return true;
  }

  record.count += 1;
  return false;
}

export async function submitCandidateApplication(
  formData: FormData
): Promise<ServerActionResponse> {
  try {
    // 1. Extract Client IP for Rate Limiting
    const reqHeaders = headers();
    const forwardedFor = reqHeaders.get('x-forwarded-for');
    const clientIp = forwardedFor ? forwardedFor.split(',')[0].trim() : '127.0.0.1';

    if (isRateLimited(`app_submit_${clientIp}`)) {
      return {
        success: false,
        error: 'Too many submissions. Please wait a minute before trying again.',
      };
    }

    // 2. Parse Raw FormData into Structured Object
    const rawEducationData = formData.get('educationData');
    let parsedEducation: unknown[] = [];
    if (typeof rawEducationData === 'string') {
      try {
        parsedEducation = JSON.parse(rawEducationData);
      } catch {
        return {
          success: false,
          error: 'Malformed education data payload.',
        };
      }
    }

    const payload = {
      jobId: formData.get('jobId'),
      fullName: formData.get('fullName'),
      email: formData.get('email'),
      phone: formData.get('phone'),
      dob: formData.get('dob'),
      gender: formData.get('gender'),
      currentCity: formData.get('currentCity'),
      permanentAddress: formData.get('permanentAddress'),
      skills: formData.get('skills'),
      portfolioUrl: formData.get('portfolioUrl'),
      linkedinUrl: formData.get('linkedinUrl'),
      professionalProfileUrl: formData.get('professionalProfileUrl') || undefined,
      noticePeriod: formData.get('noticePeriod'),
      message: formData.get('message'),
      agreedToTerms: formData.get('agreedToTerms') === 'on' || formData.get('agreedToTerms') === 'true',
      educationData: parsedEducation,
    };

    // 3. Strict Server-Side Validation via Zod
    const validationResult = CandidateApplicationSchema.safeParse(payload);
    if (!validationResult.success) {
      const flattenedErrors = validationResult.error.flatten().fieldErrors;
      return {
        success: false,
        error: 'Validation failed. Please review your input fields.',
        fieldErrors: flattenedErrors,
      };
    }

    const validData: CandidateApplicationInput = validationResult.data;

    // 4. Check for Existing Submissions (Duplicate Detection)
    // CRITICAL SECURITY ENHANCEMENT:
    // Do NOT return the private tracking URL in the public HTTP response!
    // Returning trackingUrl directly enables unauthenticated third parties to enumerate applicants
    // and access private status portals. Instead, dispatch an email to the verified applicant.
    const isDuplicate = await checkExistingApplication(validData.email, validData.jobId);
    if (isDuplicate) {
      // Dispatches tracking link privately to applicant's email
      await dispatchTrackingEmailAsync(validData.email, validData.fullName);

      return {
        success: true,
        message: 'Your application is already on file. We have sent your active status tracking details to your email.',
      };
    }

    // 5. Decouple Database & Notification via Async Event Queue
    // (e.g. Inngest / QStash / AWS SQS) to maintain serverless response under 200ms
    await dispatchApplicationEventToQueue(validData);

    return {
      success: true,
      message: 'Application blueprint received successfully.',
    };
  } catch (error) {
    // Log error internally with correlation ID; do not leak internal stack traces
    console.error('[Application Submission Error]:', error);
    return {
      success: false,
      error: 'An unexpected architectural service error occurred. Please try again later.',
    };
  }
}

// Mock database duplicate check
async function checkExistingApplication(email: string, jobId: string): Promise<boolean> {
  // In production: await db.application.findUnique({ where: { email_jobId: { email, jobId } } });
  return false;
}

// Mock secure background email notification
async function dispatchTrackingEmailAsync(email: string, name: string): Promise<void> {
  // Dispatches transactional email with secure, time-limited magic token
}

// Mock async queue producer
async function dispatchApplicationEventToQueue(data: CandidateApplicationInput): Promise<void> {
  // Dispatches event to queue worker for resume processing, ATS sync, and DB commit
}

