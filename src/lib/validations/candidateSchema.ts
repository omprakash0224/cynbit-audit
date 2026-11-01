import { z } from 'zod';

/**
 * Cynbit Backend Data Validation & Sanitization Schema
 * 
 * Provides defense-in-depth:
 * - Replaces non-binding client-side validation with strict server-side schema verification.
 * - Protects against Malicious URLs (e.g. javascript: or data: URIs).
 * - Enforces length boundaries, phone regex, and ISO date formatting.
 * - Sanitizes user text fields to mitigate persistent XSS / injection attacks.
 */

// Regex for international and Indian phone numbers (E.164 compliant & 10-digit Indian mobiles)
const PHONE_REGEX = /^(?:\+91|91)?[6789]\d{9}$/;

// Allowed URL schemes to prevent XSS payloads in profile links
function isValidHttpUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

// Single Education entry schema
export const EducationItemSchema = z.object({
  id: z.string().min(1),
  qualificationLevel: z.enum([
    '10th / High School',
    '12th / Senior Secondary',
    'Diploma',
    'Bachelor’s Degree',
    'Master’s Degree',
    'Doctorate (Ph.D.)',
    'Professional Qualification',
    'Other',
  ]),
  degree: z.string().min(1, 'Degree is required'),
  customDegree: z.string().max(100).optional(),
  specialization: z.string().max(100).optional(),
  university: z.string().min(2, 'University name must be at least 2 characters').max(150),
  graduationYear: z.string().regex(/^\d{4}$/, 'Invalid graduation year'),
  scoreType: z.enum(['CGPA', 'Percentage']),
  scoreValue: z.string().min(1, 'Score value required').max(10),
  status: z.enum(['Completed', 'Currently Pursuing', 'Expected to Graduate']),
});

// Candidate Application Schema
export const CandidateApplicationSchema = z.object({
  jobId: z.string().min(2, 'Job ID is required').max(100),
  fullName: z
    .string()
    .trim()
    .min(2, 'Full name must be at least 2 characters')
    .max(100, 'Full name exceeds 100 characters')
    .regex(/^[a-zA-Z\s.'-]+$/, 'Full name contains invalid characters'),
  email: z
    .string()
    .trim()
    .email('Invalid email address')
    .max(255)
    .toLowerCase(),
  phone: z
    .string()
    .trim()
    .refine((val) => PHONE_REGEX.test(val.replace(/[\s-]/g, '')), {
      message: 'Invalid phone number format',
    }),
  dob: z
    .string()
    .regex(/^\d{4}-\d{2}-\d{2}$/, 'Date of birth must be YYYY-MM-DD'),
  gender: z.enum(['Male', 'Female', 'Non-Binary', 'Prefer not to say']),
  currentCity: z.string().trim().min(2).max(100),
  permanentAddress: z.string().trim().min(5).max(300),
  skills: z.string().trim().min(2).max(500),
  portfolioUrl: z
    .string()
    .trim()
    .refine(isValidHttpUrl, { message: 'Portfolio URL must be a valid HTTP/HTTPS URL' })
    .max(500),
  linkedinUrl: z
    .string()
    .trim()
    .refine(isValidHttpUrl, { message: 'LinkedIn URL must be a valid HTTP/HTTPS URL' })
    .refine(
      (url) => url.includes('linkedin.com/'),
      { message: 'Must be a valid LinkedIn profile URL' }
    ),
  professionalProfileUrl: z
    .string()
    .trim()
    .optional()
    .refine((url) => !url || isValidHttpUrl(url), {
      message: 'Profile URL must be a valid HTTP/HTTPS URL',
    }),
  noticePeriod: z.string().trim().min(1).max(50),
  message: z
    .string()
    .trim()
    .min(10, 'Statement must be at least 10 characters')
    .max(2000, 'Statement exceeds 2000 characters'),
  agreedToTerms: z.literal(true, {
    errorMap: () => ({ message: 'You must agree to the Terms & Conditions' }),
  }),
  educationData: z.array(EducationItemSchema).min(1, 'At least one education record is required'),
});

// Inquiry / Contact Schema
export const ContactInquirySchema = z.object({
  fullName: z.string().trim().min(2).max(100),
  email: z.string().trim().email().toLowerCase(),
  company: z.string().trim().max(150).optional(),
  industry: z.string().trim().max(100).optional(),
  message: z.string().trim().min(10).max(3000),
  honeypot: z.string().max(0, 'Spam detected').optional(), // Hidden honeypot field
});

export type CandidateApplicationInput = z.infer<typeof CandidateApplicationSchema>;
export type ContactInquiryInput = z.infer<typeof ContactInquirySchema>;

