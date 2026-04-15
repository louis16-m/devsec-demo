from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


SCRIPT_PATH = Path(__file__).resolve().parents[1] / ".github" / "scripts" / "validate_pr_submission.py"
SPEC = importlib.util.spec_from_file_location("validate_pr_submission", SCRIPT_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
SPEC.loader.exec_module(MODULE)

_find_empty_sections = MODULE._find_empty_sections
_find_missing_headings = MODULE._find_missing_headings
_find_unchecked_checklist_items = MODULE._find_unchecked_checklist_items
_extract_issue_numbers_from_related_section = MODULE._extract_issue_numbers_from_related_section
_extract_required_branch_from_issue = MODULE._extract_required_branch_from_issue
_find_protected_assignment_paths = MODULE._find_protected_assignment_paths
_is_assignment_submission = MODULE._is_assignment_submission
_validate_assignment_linking = MODULE._validate_assignment_linking
_validate_protected_assignment_paths = MODULE._validate_protected_assignment_paths


VALID_BODY = """## Assignment Summary
- Implemented the requested task.

## Related Issue
- Closes #12

## Target Assignment Branch
- assignment/secure-password-reset

## Design Note
- Planned to reuse Django auth and keep routes inside one student app.

## Security Impact
- Added protected views and used built-in auth flows.

## Changes Made
- Added routes, forms, and tests.

## Validation
- Ran local checks and manual auth flow testing.

## AI Assistance Used
- Used AI for limited concept explanations only.

## What AI Helped With
- Asked for a refresher on Django auth views.

## What I Changed From AI Output
- Rewrote the form and redirect handling myself.

## Security Decisions I Made Myself
- Used login-required protection and built-in password validation.

## Authorship Affirmation
- I can explain the architecture, security controls, and tests in this PR.

## Checklist
- [x] I linked the related issue
- [x] I linked exactly one assignment issue in the Related Issue section
- [x] I started from the active assignment branch for this task
- [x] My pull request targets the exact assignment branch named in the linked issue
- [x] I included a short design note and meaningful validation details
- [x] I disclosed any AI assistance used for this submission
- [x] I can explain the key code paths, security decisions, and tests in this PR
- [x] I tested the change locally
- [x] I updated any directly related documentation or configuration, or none was required
"""

VALID_ISSUE_BODY = """## Learning objective
- Learn secure password reset design.

## Required submission branch

assignment/secure-password-reset
"""


class ValidatePrSubmissionTests(unittest.TestCase):
    def test_valid_body_has_no_missing_or_empty_sections(self) -> None:
        self.assertEqual(_find_missing_headings(VALID_BODY), [])
        self.assertEqual(_find_empty_sections(VALID_BODY), [])
        self.assertEqual(_find_unchecked_checklist_items(VALID_BODY), [])

    def test_missing_heading_is_reported(self) -> None:
        body = VALID_BODY.replace("## Validation\n- Ran local checks and manual auth flow testing.\n\n", "")
        self.assertIn("Validation", _find_missing_headings(body))

    def test_none_only_section_is_reported_as_empty(self) -> None:
        body = VALID_BODY.replace(
            "## What AI Helped With\n- Asked for a refresher on Django auth views.\n\n",
            "## What AI Helped With\n- _None_\n\n",
        )
        self.assertIn("What AI Helped With", _find_empty_sections(body))

    def test_unchecked_required_checkbox_is_reported(self) -> None:
        body = VALID_BODY.replace(
            "- [x] I disclosed any AI assistance used for this submission",
            "- [ ] I disclosed any AI assistance used for this submission",
        )
        self.assertIn(
            "I disclosed any AI assistance used for this submission",
            _find_unchecked_checklist_items(body),
        )

    def test_extract_issue_number_from_related_section(self) -> None:
        self.assertEqual(_extract_issue_numbers_from_related_section(VALID_BODY), [12])

    def test_extract_required_branch_from_issue_body(self) -> None:
        self.assertEqual(
            _extract_required_branch_from_issue(VALID_ISSUE_BODY),
            "assignment/secure-password-reset",
        )

    def test_assignment_submission_detected_from_assignment_base_branch(self) -> None:
        self.assertTrue(_is_assignment_submission("", "assignment/secure-password-reset"))

    def test_assignment_submission_detected_from_template_markers(self) -> None:
        self.assertTrue(_is_assignment_submission(VALID_BODY, "main"))

    def test_non_assignment_pr_is_not_detected_from_plain_body(self) -> None:
        self.assertFalse(
            _is_assignment_submission("## Summary\n- Internal maintenance update.\n", "main"),
        )

    def test_protected_assignment_paths_detect_instructor_and_ci_files(self) -> None:
        self.assertEqual(
            _find_protected_assignment_paths(
                [
                    "docs/assignment-issues/secure-password-reset.md",
                    "docs/review-workflow.md",
                    ".github/workflows/ci.yml",
                    "student_app/views.py",
                ],
            ),
            [
                ".github/workflows/ci.yml",
                "docs/assignment-issues/secure-password-reset.md",
                "docs/review-workflow.md",
            ],
        )

    def test_protected_assignment_paths_allow_normal_student_code(self) -> None:
        self.assertEqual(
            _find_protected_assignment_paths(
                [
                    "student_app/views.py",
                    "student_app/tests.py",
                    "README.md",
                ],
            ),
            [],
        )

    def test_assignment_linking_accepts_matching_issue_and_branch(self) -> None:
        original_fetch = MODULE._fetch_issue_body
        MODULE._fetch_issue_body = lambda issue_number: VALID_ISSUE_BODY
        try:
            self.assertEqual(
                _validate_assignment_linking(VALID_BODY, "assignment/secure-password-reset"),
                [],
            )
        finally:
            MODULE._fetch_issue_body = original_fetch

    def test_assignment_linking_rejects_wrong_base_branch(self) -> None:
        original_fetch = MODULE._fetch_issue_body
        MODULE._fetch_issue_body = lambda issue_number: VALID_ISSUE_BODY
        try:
            errors = _validate_assignment_linking(VALID_BODY, "assignment/fix-open-redirects")
        finally:
            MODULE._fetch_issue_body = original_fetch

        self.assertTrue(any("requires branch 'assignment/secure-password-reset'" in error for error in errors))

    def test_assignment_linking_requires_exactly_one_issue(self) -> None:
        body = VALID_BODY.replace("Closes #12", "Closes #12 and Fixes #13")
        errors = _validate_assignment_linking(body, "assignment/secure-password-reset")
        self.assertTrue(any("exactly one assignment issue" in error for error in errors))

    def test_assignment_linking_requires_issue_branch_marker(self) -> None:
        original_fetch = MODULE._fetch_issue_body
        MODULE._fetch_issue_body = lambda issue_number: "## Learning objective\n- Missing branch marker.\n"
        try:
            errors = _validate_assignment_linking(VALID_BODY, "assignment/secure-password-reset")
        finally:
            MODULE._fetch_issue_body = original_fetch

        self.assertTrue(any("missing a valid 'Required submission branch' section" in error for error in errors))

    def test_assignment_linking_skips_non_assignment_prs_to_main(self) -> None:
        non_assignment_body = """## Summary
- Internal instructor maintenance update.
"""
        self.assertEqual(_validate_assignment_linking(non_assignment_body, "main"), [])

    def test_protected_path_validation_skips_non_assignment_prs(self) -> None:
        original_fetch = MODULE._fetch_pull_request_files
        MODULE._fetch_pull_request_files = lambda: [".github/workflows/ci.yml"]
        try:
            self.assertEqual(
                _validate_protected_assignment_paths("## Summary\n- Internal instructor maintenance update.\n", "main"),
                [],
            )
        finally:
            MODULE._fetch_pull_request_files = original_fetch

    def test_protected_path_validation_rejects_assignment_prs_touching_admin_files(self) -> None:
        original_fetch = MODULE._fetch_pull_request_files
        MODULE._fetch_pull_request_files = lambda: [
            ".github/workflows/ci.yml",
            "scripts/create_assignment_issues.sh",
            "student_app/views.py",
        ]
        try:
            errors = _validate_protected_assignment_paths(VALID_BODY, "assignment/secure-password-reset")
        finally:
            MODULE._fetch_pull_request_files = original_fetch

        self.assertTrue(any("must not modify instructor-facing" in error for error in errors))
        self.assertTrue(any("Restricted file changed: .github/workflows/ci.yml" == error for error in errors))
        self.assertTrue(any("Restricted file changed: scripts/create_assignment_issues.sh" == error for error in errors))

    def test_main_skips_non_assignment_pull_requests(self) -> None:
        original_load = MODULE._load_event_payload
        MODULE._load_event_payload = lambda: {
            "pull_request": {
                "body": "## Summary\n- Internal instructor maintenance update.\n",
                "base": {"ref": "main"},
            },
        }
        try:
            self.assertEqual(MODULE.main(), 0)
        finally:
            MODULE._load_event_payload = original_load

    def test_main_requires_template_for_assignment_pull_requests(self) -> None:
        original_load = MODULE._load_event_payload
        MODULE._load_event_payload = lambda: {
            "pull_request": {
                "body": "",
                "base": {"ref": "assignment/secure-password-reset"},
            },
        }
        try:
            self.assertEqual(MODULE.main(), 1)
        finally:
            MODULE._load_event_payload = original_load


if __name__ == "__main__":
    unittest.main()
