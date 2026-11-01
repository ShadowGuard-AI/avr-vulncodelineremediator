import argparse
import logging
import os
import re
import subprocess
import sys
import tempfile
from typing import List, Tuple

import requests
from bs4 import BeautifulSoup
import ast
import difflib

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class VulnerabilityDatabaseError(Exception):
    """Custom exception for vulnerability database errors."""
    pass


class CodeAnalysisError(Exception):
    """Custom exception for code analysis errors."""
    pass


class PatchGenerationError(Exception):
    """Custom exception for patch generation errors."""
    pass


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description="avr-VulnCodeLineRemediator: Automated Vulnerability Remediation Tool"
    )

    parser.add_argument(
        "--vulnerability_id",
        type=str,
        required=True,
        help="The ID of the vulnerability to remediate (e.g., CVE-2023-1234)",
    )
    parser.add_argument(
        "--codebase_path",
        type=str,
        required=True,
        help="The path to the codebase to scan.",
    )
    parser.add_argument(
        "--output_patch_path",
        type=str,
        default="patch.diff",
        help="The path to save the generated patch file. Defaults to 'patch.diff'.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply code changing patches to the files in place. Without this flag a run only writes the patch file and changes no scanned file. Suggestions that only add a comment are never applied; they are written to the patch file as manual steps.",
    )
    parser.add_argument(
        "--approval_required",
        action="store_true",
        help="With --apply, ask before applying each patch (interactive mode). Has no effect without --apply.",
    )
    parser.add_argument(
        "--exploit_db_url",
        type=str,
        default="https://www.exploit-db.com/",
        help="The base URL of the Exploit Database to use for vulnerability information.",
    )

    return parser


def fetch_vulnerability_data(vulnerability_id: str, exploit_db_url: str) -> Tuple[str, str]:
    """
    Fetches vulnerability data from a vulnerability database (e.g., Exploit Database).
    Parses the HTML content to extract relevant information, such as the vulnerability description
    and potential exploit code snippets.

    Args:
        vulnerability_id (str): The ID of the vulnerability (e.g., CVE-2023-1234).
        exploit_db_url (str): The base URL of the Exploit Database.

    Returns:
        Tuple[str, str]: A tuple containing the vulnerability description and exploit details (or None if not found).

    Raises:
        VulnerabilityDatabaseError: If an error occurs while fetching or parsing the data.
    """
    try:
        # Construct the URL for the vulnerability based on the database format.
        search_url = f"{exploit_db_url}search?value={vulnerability_id}"
        logging.info(f"Fetching vulnerability data from: {search_url}")

        response = requests.get(search_url, timeout=15)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        soup = BeautifulSoup(response.content, "html.parser")

        # Example parsing: Adjust selectors based on the actual structure of the database page.
        vulnerability_description = ""
        exploit_details = ""
        
        # What comes back as the description is the first cell of the
        # first row of the first table on a search results page. That
        # is a fragile thing to build on: it can as easily be a date or
        # an exploit title as a description, and everything downstream,
        # the keyword scan of the codebase included, takes its words
        # from this cell. Treat the fetched text as a lead, not as a
        # verified description of the named vulnerability.
        table = soup.find("table")
        if table:
            # Find all rows in the table
            rows = table.find_all("tr")
            
            # Iterate through the rows and extract data from the first column (<td>)
            for row in rows:
                cells = row.find_all("td")
                if cells:
                    # Extract the text from the first cell
                    cell_text = cells[0].get_text(strip=True)
                    vulnerability_description = cell_text  # This may need more precise selection
                    
                    # Attempt to extract exploit details (this will vary based on the database)
                    # This is a placeholder and needs to be adjusted for a real database structure
                    exploit_details = row.find("div", class_="code").get_text(strip=True) if row.find("div", class_="code") else ""
                    break # Stop after processing the first row
        
        if not vulnerability_description:
            logging.warning(f"No vulnerability information found for ID: {vulnerability_id}")
            return None, None

        return vulnerability_description, exploit_details

    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching vulnerability data: {e}")
        raise VulnerabilityDatabaseError(f"Failed to fetch vulnerability data: {e}")
    except Exception as e:
        logging.error(f"Error parsing vulnerability data: {e}")
        raise VulnerabilityDatabaseError(f"Failed to parse vulnerability data: {e}")


def identify_vulnerable_code_lines(
    codebase_path: str, vulnerability_description: str, exploit_details: str
) -> List[Tuple[str, int]]:
    """
    Identifies code lines in the codebase based on the vulnerability description
    and exploit details. Each file is parsed with ast.parse only to confirm it
    parses; the match itself is a keyword line scan over the file lines, using
    the words from the fetched description and exploit text.

    Args:
        codebase_path (str): The path to the codebase.
        vulnerability_description (str): The vulnerability description.
        exploit_details (str): The exploit details.

    Returns:
        List[Tuple[str, int]]: A list of tuples, where each tuple contains the filename and line number
                                 of a vulnerable code line.

    Raises:
        CodeAnalysisError: If an error occurs during code analysis.
    """
    vulnerable_lines = []
    try:
        for root, _, files in os.walk(codebase_path):
            for file in files:
                if file.endswith(".py"):  # Analyze Python files
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, "r", encoding="utf-8") as f:
                            code = f.read()
                            ast.parse(code)

                            # The file is parsed only to confirm it is
                            # valid Python worth scanning. The match
                            # itself is a single pass over the lines:
                            # walking every AST node and re-reading its
                            # whole line range re-reported the same line
                            # once per enclosing node, and ast.Module
                            # has no lineno, which failed the whole file.
                            keywords = re.split(r'\W+', vulnerability_description + " " + exploit_details)
                            # No stopword filtering, and the test below
                            # is substring, not word, matching. A keyword
                            # like the survives the length test and marks
                            # nearly every line, and a short keyword
                            # matches inside longer words. The line list
                            # this produces is a coarse net by design;
                            # the fix stage only fires on three exact
                            # call shapes, which is what keeps the net
                            # from turning into mass edits.
                            keywords = [k.lower() for k in keywords if len(k) > 2]

                            with open(filepath, "r", encoding="utf-8") as src:
                                for lineno, raw in enumerate(src, start=1):
                                    line = raw.strip().lower()
                                    if any(keyword in line for keyword in keywords):
                                        vulnerable_lines.append((filepath, lineno))

                    except Exception as e:
                        logging.error(f"Error analyzing file {filepath}: {e}")
                        continue  # Move to the next file

    except Exception as e:
        logging.error(f"Error during code analysis: {e}")
        raise CodeAnalysisError(f"Failed to analyze codebase: {e}")

    return vulnerable_lines

def suggest_fixes(filepath: str, vulnerable_line_number: int, vulnerability_description: str, exploit_details: str) -> str:
    """
    Suggests a fix for a vulnerable line of code based on the vulnerability description and exploit details.
    This is a placeholder implementation; a real implementation would use more sophisticated techniques
    like pattern matching, code transformation, or calls to external security analysis tools.

    Args:
        filepath (str): The path to the file containing the vulnerable line.
        vulnerable_line_number (int): The line number of the vulnerable line.
        vulnerability_description (str): The vulnerability description.
        exploit_details (str): The exploit details.

    Returns:
        str: The suggested fix for the vulnerable line.  Returns an empty string if no fix is suggested.

    """

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
            if 1 <= vulnerable_line_number <= len(lines):
                vulnerable_line = lines[vulnerable_line_number - 1]

                # Placeholder: Suggest a fix based on simple keyword replacement
                if "input(" in vulnerable_line.lower():
                    suggested_fix = vulnerable_line.replace("input(", "getpass.getpass(") # import getpass must be manually added

                elif "os.system(" in vulnerable_line.lower():
                    suggested_fix = "# WARNING: os.system is a security risk, replace with subprocess.run\n" + vulnerable_line # User needs to manually implement

                elif "pickle.load(" in vulnerable_line.lower():
                    suggested_fix = "# WARNING: pickle.load can load malicious data. Replace with a safer serializer such as json.loads \n" + vulnerable_line # User needs to manually implement
                else:
                    suggested_fix = ""  # No fix suggestion

                return suggested_fix.rstrip('\n')  # remove trailing newline.

            else:
                logging.warning(f"Vulnerable line number {vulnerable_line_number} is out of range for file {filepath}")
                return ""  # Line number out of range.


    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        return ""
    except Exception as e:
        logging.error(f"Error generating fix: {e}")
        return ""



def generate_patch(filepath: str, vulnerable_line_number: int, suggested_fix: str) -> str:
    """
    Generates a patch file that applies the suggested fix to the vulnerable code.
    Uses the 'diff' command to create a unified diff format patch.

    Args:
        filepath (str): The path to the file to be patched.
        vulnerable_line_number (int): The line number of the vulnerable line.
        suggested_fix (str): The suggested fix for the vulnerable line.

    Returns:
        str: The content of the generated patch file.

    Raises:
        PatchGenerationError: If an error occurs during patch generation.
    """
    try:
        # The original temp file written here is never actually read:
        # the diff below re-reads the target file and the modified
        # temp. It is kept as a byproduct of how this function grew,
        # and on an exception before the cleanup at the bottom both
        # temp files are left behind in the temp directory.
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".tmp") as original_file:
            with open(filepath, "r", encoding="utf-8") as f:
                original_code = f.readlines()
                original_file.writelines(original_code)
            original_file_path = original_file.name

        # Create a temporary file with the modified code.
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".tmp") as modified_file:
            modified_code = original_code[:]  # Copy original code
            if 1 <= vulnerable_line_number <= len(modified_code):
                modified_code[vulnerable_line_number - 1] = suggested_fix + "\n"
            else:
                logging.warning(f"Vulnerable line number {vulnerable_line_number} is out of range for file {filepath}")
                return ""

            modified_file.writelines(modified_code)
            modified_file_path = modified_file.name

        # Generate the diff using difflib
        with open(filepath, "r", encoding="utf-8") as f:
          original_lines = f.readlines()

        with open(modified_file_path, "r", encoding="utf-8") as f:
          modified_lines = f.readlines()

        diff = difflib.unified_diff(original_lines, modified_lines, fromfile=filepath, tofile=filepath)
        patch_content = ''.join(diff)

        # Clean up temporary files
        os.remove(original_file_path)
        os.remove(modified_file_path)

        return patch_content

    except Exception as e:
        logging.error(f"Error generating patch: {e}")
        raise PatchGenerationError(f"Failed to generate patch: {e}")


def apply_patch(filepath: str, patch_content: str) -> None:
    """
    Applies a patch file to a file.  Uses the 'patch' command to apply the changes.

    Args:
        filepath (str): The path to the file to be patched.
        patch_content (str): The content of the patch file.

    Raises:
        PatchGenerationError: If an error occurs while applying the patch.
    """
    try:
        # Write the patch content to a temporary file.
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".patch") as patch_file:
            patch_file.write(patch_content)
            patch_file_path = patch_file.name

        # Apply the patch using the 'patch' command.
        command = ["patch", "-u", filepath, patch_file_path]
        result = subprocess.run(command, capture_output=True, text=True, check=False)

        if result.returncode != 0:
            logging.error(f"Error applying patch: {result.stderr}")
            raise PatchGenerationError(f"Failed to apply patch: {result.stderr}")

        logging.info(f"Patch applied successfully to {filepath}")

        # Clean up the temporary patch file.
        os.remove(patch_file_path)

    except FileNotFoundError as e:
        logging.error(f"File not found: {e}")
        raise PatchGenerationError(f"File not found: {e}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error applying patch: {e.stderr}")
        raise PatchGenerationError(f"Failed to apply patch: {e.stderr}")
    except Exception as e:
        logging.error(f"Error applying patch: {e}")
        raise PatchGenerationError(f"Failed to apply patch: {e}")


def is_manual_suggestion(original_line: str, suggested_fix: str) -> bool:
    """
    A suggestion is a manual step when it changes no code: once its
    comment lines are removed, what is left is the original line,
    unchanged. The os.system and pickle.load suggestions are of this
    shape (a warning comment above the line they name), so the named
    line would keep running if the comment were applied and the run
    logged it as a fix. Manual steps are never auto applied.
    """
    code_lines = [
        line for line in suggested_fix.splitlines()
        if not line.lstrip().startswith("#")
    ]
    return [line.rstrip() for line in code_lines] == [original_line.rstrip("\n")]


def read_line(filepath: str, line_number: int) -> str:
    """Reads one line of a file, or an empty string when out of range."""
    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()
    if 1 <= line_number <= len(lines):
        return lines[line_number - 1]
    return ""


def ensure_getpass_import(filepath: str) -> None:
    """
    The input() fix rewrites a call to getpass.getpass, which is a
    NameError in a file that never imported getpass. Add the import
    once, after that file's patches have been applied, when an applied
    fix uses getpass and the file does not import it yet.
    """
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
    if "getpass.getpass(" in content and "import getpass" not in content:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("import getpass\n" + content)
        logging.info(f"Added import getpass to {filepath}")


def main():
    """
    Main function to orchestrate the vulnerability remediation process.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    try:
        # 1. Fetch vulnerability data from the database.
        vulnerability_description, exploit_details = fetch_vulnerability_data(
            args.vulnerability_id, args.exploit_db_url
        )

        if not vulnerability_description:
            logging.error(f"Vulnerability with ID '{args.vulnerability_id}' not found.")
            sys.exit(1)


        if not os.path.isdir(args.codebase_path):
            logging.error(f"Codebase path is not a directory: {args.codebase_path}")
            sys.exit(1)

        # 2. Identify vulnerable code lines.
        vulnerable_lines = identify_vulnerable_code_lines(
            args.codebase_path, vulnerability_description, exploit_details
        )

        if not vulnerable_lines:
            logging.info("No vulnerable code lines found.")
            sys.exit(0)

        logging.info(f"Found {len(vulnerable_lines)} potentially vulnerable lines.")


        # 3. Collect suggestions first, against the files as scanned.
        # Nothing is written to a scanned file in this step, so every
        # line number still refers to the original file.
        entries = []
        for filepath, line_number in vulnerable_lines:
            suggested_fix = suggest_fixes(filepath, line_number, vulnerability_description, exploit_details)
            if not suggested_fix:
                logging.warning(f"No fix suggested for {filepath}:{line_number}")
                continue
            original_line = read_line(filepath, line_number)
            entries.append({
                "filepath": filepath,
                "line_number": line_number,
                "suggested_fix": suggested_fix,
                "manual": is_manual_suggestion(original_line, suggested_fix),
            })

        # Order entries per file from the highest line number down, so
        # applying one patch cannot shift the line numbers of the
        # patches that come after it in the same file.
        entries.sort(key=lambda e: (e["filepath"], -e["line_number"]))

        # 4. Build the patch file. Code changing suggestions become
        # diffs, generated against the original files before any
        # applying. Comment only suggestions become manual steps in
        # the patch file and are never auto applied.
        all_patches = ""
        applied_files = []
        for entry in entries:
            filepath = entry["filepath"]
            line_number = entry["line_number"]
            suggested_fix = entry["suggested_fix"]
            logging.info(f"Suggested fix for {filepath}:{line_number}: {suggested_fix}")
            if entry["manual"]:
                entry["patch_content"] = ""
                all_patches += (
                    f"# MANUAL STEP (not auto-applied): {filepath}:{line_number}\n"
                    f"# This suggestion changes no code. Apply it by hand:\n"
                    f"# {suggested_fix}\n\n"
                )
                logging.info(f"Manual step (not applied): {filepath}:{line_number} changes no code and needs a hand fix.")
                continue
            patch_content = generate_patch(filepath, line_number, suggested_fix)
            if patch_content:
                print(f"Generated patch:\n{patch_content}")
                entry["patch_content"] = patch_content
                all_patches += patch_content
            else:
                entry["patch_content"] = ""
                logging.warning(f"No patch generated for {filepath}:{line_number}")

        # Save all patches and manual steps to a single file.
        if all_patches:
            with open(args.output_patch_path, "w", encoding="utf-8") as f:
                f.write(all_patches)
            logging.info(f"All generated patches saved to {args.output_patch_path}")

        # 5. Apply only under --apply, and only the code changing
        # patches, in the bottom up order set above. A default run
        # stops at the patch file and changes no scanned file.
        if not args.apply:
            logging.info("No files changed. Pass --apply to apply the code changing patches in place; manual steps are never auto applied.")
        else:
            for entry in entries:
                if entry["manual"] or not entry["patch_content"]:
                    continue
                filepath = entry["filepath"]
                if args.approval_required:
                    approval = input(f"Apply patch to {filepath} (y/n)? ").lower()
                    if approval != "y":
                        logging.info(f"Patch for {filepath} not applied.")
                        continue
                # Regenerate the diff against the file as it stands
                # now, in this bottom up order: a diff written against
                # the original file can fail on context lines that a
                # neighbouring patch in the same file already changed.
                # The patch file saved above keeps the original diffs,
                # which replay against the original file.
                fresh_patch = generate_patch(filepath, entry["line_number"], entry["suggested_fix"])
                apply_patch(filepath, fresh_patch)
                applied_files.append(filepath)
            for filepath in dict.fromkeys(applied_files):
                ensure_getpass_import(filepath)


    except VulnerabilityDatabaseError as e:
        logging.error(f"Vulnerability database error: {e}")
        sys.exit(1)
    except CodeAnalysisError as e:
        logging.error(f"Code analysis error: {e}")
        sys.exit(1)
    except PatchGenerationError as e:
        logging.error(f"Patch generation error: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()


