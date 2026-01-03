#!/usr/bin/env python
#
# Copyright 2016 Hannes Juutilainen
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import subprocess
import json
import hashlib
import time

from autopkglib import Processor, ProcessorError

__all__ = ["VirusTotalAnalyzer"]

# VirusTotal was kind enough to give this processor its own API key so that it can be
# used as-is without further configuring. Please don't abuse this.
DEFAULT_API_KEY = "3858a94a911f47707717f6d090dbb8f86badb750b0f7bfe74a55c0c6143e3de6"

# Default options
DEFAULT_SLEEP = 60
ALWAYS_REPORT_DEFAULT = False
AUTO_SUBMIT_DEFAULT = False
AUTO_SUBMIT_MAX_SIZE_DEFAULT = 419430400  # 400MB


class VirusTotalAnalyzer(Processor):
    """Queries VirusTotal database for information about the given file"""
    input_variables = {
        "pathname": {
            "required": False,
            "description": "File path to analyze.",
        },
        "VIRUSTOTAL_ALWAYS_REPORT": {
            "required": False,
            "description": "Always request a report instead of only for new downloads",
        },
        "VIRUSTOTAL_AUTO_SUBMIT": {
            "required": False,
            "description": "If item is not found in VirusTotal database, automatically submit it for scanning.",
        },
        "CURL_PATH": {
            "required": False,
            "default": "/usr/bin/curl",
            "description": "Path to curl binary. Defaults to /usr/bin/curl.",
        },
    }
    output_variables = {
        "virus_total_analyzer_summary_result": {
            "description": "Description of interesting results."
        },
    }
    description = __doc__

    def fetch_content(self, url, headers=None, form_parameters=None, data_parameters=None, curl_options=None, return_status=False):
        """Returns content retrieved by curl, given an url and an optional
        dictionaries of header-name/value mappings and parameters.
        Logic here borrowed from URLTextSearcher processor.

        Keyword arguments:
        :param url: The URL to fetch
        :type url: str None
        :param headers: Dictionary of header-names and values
        :type headers: dict None
        :param form_parameters: Dictionary of items for '--form'
        :type form_parameters: dict None
        :param data_parameters: Dictionary of items for '--data'
        :type data_parameters: dict None
        :param curl_options: Array of arguments to pass to curl
        :type curl_options: list None
        :param return_status: Return HTTP status code along with content
        :type return_status: bool False
        :returns: content as string, or (content, status_code) tuple if return_status=True
        """

        try:
            cmd = [self.env['CURL_PATH'], '--location']

            # Add status code output if requested (for v3 API)
            if return_status:
                cmd.extend(['-w', '\n%{http_code}'])

            if curl_options:
                cmd.extend(curl_options)
            if headers:
                for header, value in headers.items():
                    cmd.extend(['--header', '%s: %s' % (header, value)])
            if form_parameters:
                for form_parameter, value in form_parameters.items():
                    cmd.extend(['--form', '%s=%s' % (form_parameter, value)])
            if data_parameters:
                for data_parameter, value in data_parameters.items():
                    cmd.extend(['--data', '%s=%s' % (data_parameter, value)])
            cmd.append(url)
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            (data, stderr) = proc.communicate()

            if return_status:
                # Split content and status code
                data_str = data.decode('utf-8') if isinstance(data, bytes) else data
                lines = data_str.rsplit('\n', 1)
                if len(lines) == 2:
                    content = lines[0]
                    try:
                        status_code = int(lines[1])
                    except (ValueError, TypeError):
                        # Malformed status code, treat as error
                        self.output("Warning: Could not parse HTTP status code from curl output")
                        content = data_str
                        status_code = 0
                else:
                    content = data_str
                    status_code = 0

                # Don't raise error for expected HTTP statuses (404 is valid for "not found")
                if proc.returncode and status_code not in [404]:
                    raise ProcessorError(
                        'Could not retrieve URL %s: %s' % (url, stderr.decode('utf-8') if isinstance(stderr, bytes) else stderr))

                return content, status_code
            else:
                if proc.returncode:
                    raise ProcessorError(
                        'Could not retrieve URL %s: %s' % (url, stderr.decode('utf-8') if isinstance(stderr, bytes) else stderr))
                return data.decode('utf-8') if isinstance(data, bytes) else data

        except OSError:
            raise ProcessorError('Could not retrieve URL: %s' % url)

    def submit_file(self, file_path, api_key):
        """Submit a file to VirusTotal for scanning (API v3)

        :param file_path: Path to a file to upload
        :param api_key: API key to use
        :returns: JSON response (normalized to v2 format)
        """
        # v3 endpoint for getting upload URL
        url = "https://www.virustotal.com/api/v3/files/upload_url"

        # v3 uses header authentication
        headers = {"x-apikey": api_key}

        # Get the upload URL
        try:
            f, status_code = self.fetch_content(url, headers, return_status=True)
        except ProcessorError as e:
            self.output("Network error getting upload URL: %s" % e)
            return {
                'response_code': 999,
                'verbose_msg': 'Requesting upload URL failed: %s' % str(e),
                'scan_id': None,
                'permalink': None
            }

        if status_code != 200:
            self.output("HTTP error getting upload URL: %d" % status_code)
            return {
                'response_code': 999,
                'verbose_msg': 'HTTP %d error getting upload URL' % status_code,
                'scan_id': None,
                'permalink': None
            }

        try:
            upload_response = json.loads(f)
        except (ValueError, KeyError, TypeError) as e:
            self.output("Response was: %s" % f)
            self.output("JSON format error: %s" % e)
            return {
                'response_code': 999,
                'verbose_msg': 'Requesting upload URL failed: invalid JSON',
                'scan_id': None,
                'permalink': None
            }

        # v3 returns upload URL directly in 'data' field (string)
        upload_url = upload_response.get('data', None)
        if upload_url is None:
            self.output("No upload URL in response: %s" % upload_response)
            return {
                'response_code': 999,
                'verbose_msg': 'No upload URL returned',
                'scan_id': None,
                'permalink': None
            }

        # Upload the file
        file_path_for_post = "@%s" % file_path
        form_params = {"file": file_path_for_post}

        try:
            f, status_code = self.fetch_content(upload_url, headers, form_params, return_status=True)
        except ProcessorError as e:
            self.output("Network error uploading file: %s" % e)
            return {
                'response_code': 999,
                'verbose_msg': 'File upload failed: %s' % str(e),
                'scan_id': None,
                'permalink': None
            }

        if status_code != 200:
            self.output("HTTP error uploading file: %d" % status_code)
            return {
                'response_code': 999,
                'verbose_msg': 'HTTP %d error uploading file' % status_code,
                'scan_id': None,
                'permalink': None
            }

        try:
            v3_response = json.loads(f)
        except (ValueError, KeyError, TypeError) as e:
            self.output("Response was: %s" % f)
            self.output("JSON format error: %s" % e)
            return {
                'response_code': 999,
                'verbose_msg': 'Request failed: invalid JSON response',
                'scan_id': None,
                'permalink': None
            }

        # Normalize v3 upload response to v2 format
        return self._normalize_v3_upload_response(v3_response)

    def report_for_hash(self, file_hash, api_key):
        """Request a VirusTotal report for a hash (API v3)

        :param file_hash: md5, sha1 or sha256 hash
        :param api_key: API key to use
        :returns: JSON response (normalized to v2 format)
        """
        # v3 endpoint with hash in URL path
        url = "https://www.virustotal.com/api/v3/files/%s" % file_hash

        # v3 uses header authentication
        headers = {"x-apikey": api_key}

        try:
            # v3 uses GET request (no data parameters)
            f, status_code = self.fetch_content(url, headers, return_status=True)
        except ProcessorError as e:
            # Network error
            self.output("Network error: %s" % e)
            return {
                'response_code': 999,
                'verbose_msg': 'Request failed: %s' % str(e),
                'positives': 0,
                'total': 0,
                'permalink': None
            }

        # Handle HTTP status codes
        if status_code == 404:
            # File not in database
            return {
                'response_code': 0,
                'verbose_msg': 'The requested resource is not among the finished, queued or pending scans',
                'positives': 0,
                'total': 0,
                'permalink': None
            }
        elif status_code == 429:
            # Rate limited
            self.output("Rate limited by VirusTotal API")
            return {
                'response_code': 999,
                'verbose_msg': 'Request rate limited, try again later',
                'positives': 0,
                'total': 0,
                'permalink': None
            }
        elif status_code != 200:
            # Other HTTP error
            self.output("HTTP error: %d" % status_code)
            return {
                'response_code': 999,
                'verbose_msg': 'HTTP %d error' % status_code,
                'positives': 0,
                'total': 0,
                'permalink': None
            }

        # Parse JSON response
        try:
            v3_response = json.loads(f)
        except (ValueError, KeyError, TypeError) as e:
            self.output("JSON response was: %s" % f)
            self.output("JSON format error: %s" % e)
            return {
                'response_code': 999,
                'verbose_msg': 'Invalid JSON response',
                'positives': 0,
                'total': 0,
                'permalink': None
            }

        # Normalize v3 response to v2 format
        return self._normalize_v3_response(v3_response, file_hash)

    def calculate_sha256(self, file_path):
        """Calculates a SHA256 checksum
        http://stackoverflow.com/a/3431838

        :param file_path:
        """
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    def _normalize_v3_response(self, v3_response, file_hash):
        """Convert v3 API response to v2-compatible format

        This allows main() logic to remain largely unchanged.

        :param v3_response: Raw v3 API JSON response
        :param file_hash: The file hash used in the request
        :returns: v2-compatible JSON structure
        """
        # Check for v3 error response
        if 'error' in v3_response:
            error_code = v3_response['error'].get('code', '')
            error_msg = v3_response['error'].get('message', 'Unknown error')

            if error_code == 'NotFoundError':
                # File not in database
                return {
                    'response_code': 0,
                    'verbose_msg': 'The requested resource is not among the finished, queued or pending scans',
                    'positives': 0,
                    'total': 0,
                    'permalink': None
                }
            else:
                # Other errors (rate limiting, etc.)
                return {
                    'response_code': 999,
                    'verbose_msg': error_msg,
                    'positives': 0,
                    'total': 0,
                    'permalink': None
                }

        # Extract v3 data structure
        data = v3_response.get('data', {})
        if not data:
            return {
                'response_code': 999,
                'verbose_msg': 'Unexpected API response format',
                'positives': 0,
                'total': 0,
                'permalink': None
            }

        attributes = data.get('attributes', {})
        file_id = data.get('id', file_hash)

        # Calculate positives/total from last_analysis_stats
        stats = attributes.get('last_analysis_stats', {})

        # Positives = malicious + suspicious
        positives = stats.get('malicious', 0) + stats.get('suspicious', 0)

        # Total = sum of all detection categories
        total = sum([
            stats.get('malicious', 0),
            stats.get('suspicious', 0),
            stats.get('harmless', 0),
            stats.get('undetected', 0),
            stats.get('timeout', 0),
            stats.get('failure', 0),
            stats.get('type-unsupported', 0)
        ])

        # Build v3 permalink
        permalink = "https://www.virustotal.com/gui/file/%s" % file_id if file_id else None

        # Convert last_analysis_date (Unix timestamp) to human-readable
        scan_date = attributes.get('last_analysis_date', None)
        if scan_date:
            # v2 format was like "2017-08-10 12:34:56" in UTC
            from datetime import datetime
            scan_date = datetime.utcfromtimestamp(scan_date).strftime('%Y-%m-%d %H:%M:%S')

        return {
            'response_code': 1,
            'verbose_msg': 'Scan finished, information embedded',
            'positives': positives,
            'total': total,
            'scan_id': file_id,
            'scan_date': scan_date,
            'permalink': permalink
        }

    def _normalize_v3_upload_response(self, v3_response):
        """Convert v3 upload response to v2-compatible format

        :param v3_response: Raw v3 upload API JSON response
        :returns: v2-compatible JSON structure
        """
        # Check for v3 error response
        if 'error' in v3_response:
            error_msg = v3_response['error'].get('message', 'Upload failed')
            return {
                'response_code': 999,
                'verbose_msg': error_msg,
                'scan_id': None,
                'permalink': None
            }

        # v3 upload response: {"data": {"type": "analysis", "id": "...", "links": {"self": "..."}}}
        data = v3_response.get('data', {})
        if not data:
            return {
                'response_code': 999,
                'verbose_msg': 'Unexpected upload response format',
                'scan_id': None,
                'permalink': None
            }

        analysis_id = data.get('id', '')

        # Build GUI permalink for the analysis (not the API link)
        # v3 API returns links.self which points to the API, but users need the GUI URL
        permalink = "https://www.virustotal.com/gui/analysis/%s" % analysis_id if analysis_id else None

        # Convert to v2 format
        return {
            'response_code': 1,
            'verbose_msg': 'Scan request successfully queued, come back later for the report',
            'scan_id': analysis_id,
            'permalink': permalink
        }

    def main(self):
        if self.env.get("VIRUSTOTAL_DISABLED", False):
            self.output("Skipped VirusTotal analysis...")
            return

        input_path = self.env.get("pathname", None)
        if not input_path:
            self.output("Skipping VirusTotal analysis: no input path defined.")
            return

        # Get variables and arguments
        sleep_seconds = int(self.env.get("VIRUSTOTAL_SLEEP_SECONDS", DEFAULT_SLEEP))
        auto_submit = self.env.get("VIRUSTOTAL_AUTO_SUBMIT", AUTO_SUBMIT_DEFAULT)
        auto_submit_max_size = int(self.env.get("VIRUSTOTAL_AUTO_SUBMIT_MAX_SIZE", AUTO_SUBMIT_MAX_SIZE_DEFAULT))

        api_key = self.env.get("VIRUSTOTAL_API_KEY", DEFAULT_API_KEY)
        if not api_key or api_key == "":
            raise ProcessorError("No API key available")

        force_report = self.env.get("VIRUSTOTAL_ALWAYS_REPORT",
                                    ALWAYS_REPORT_DEFAULT)
        if "download_changed" in self.env:
            if not self.env["download_changed"] and not force_report:
                # URLDownloader did not download new items,
                # so skip the analysis
                self.output("Skipping VirusTotal analysis: no new download.")
                self.env["virustotal_result"] = "SKIPPED"
                return

        # Calculate the SHA256 hash of the file for submitting
        self.output("Calculating checksum for %s" % input_path)
        input_path_hash = self.calculate_sha256(input_path)
        
        try:
            last_virus_total_request = int(
                os.environ.get('AUTOPKG_VIRUSTOTAL_LAST_RUN_TIME', 0))
        except ValueError:
            last_virus_total_request = 0
        if last_virus_total_request and sleep_seconds > 0:
            now = int(time.time())
            next_time = last_virus_total_request + sleep_seconds
            if now < next_time:
                sleep_time = next_time - now
                self.output(
                    "Sleeping %s seconds before requesting report..."
                    % sleep_time)
                time.sleep(sleep_time)

        # Request details for the calculated hash
        self.output("Requesting report...")
        json_data = self.report_for_hash(input_path_hash, api_key)

        # Parse the report
        response_code = json_data.get("response_code", None)
        self.output("Response code: %s" % response_code)
        if response_code == 0:
            # VirusTotal database did not have a match for this hash
            self.output("No information found for %s" % input_path)
            if not auto_submit:
                self.output(
                    "Consider submitting the file for analysis at https://www.virustotal.com/")
            else:
                if os.path.getsize(input_path) < auto_submit_max_size:
                    self.output("Submitting the file for analysis...")
                    json_data = self.submit_file(input_path, api_key)
                    response_code = json_data.get("response_code", None)
                    self.output("Response code: %s" % response_code)
                    verbose_msg = json_data.get("verbose_msg", None)
                    scan_id = json_data.get("scan_id", None)
                    permalink = json_data.get("permalink", None)
                    self.output("Message: %s" % verbose_msg)
                    self.output("Scan ID: %s" % scan_id)
                    self.output("Permalink: %s" % permalink)
                else:
                    self.output("File is too large to submit...")
        elif response_code == 1:
            # VirusTotal gave us details about the file
            verbose_msg = json_data.get("verbose_msg", None)
            scan_id = json_data.get("scan_id", None)
            num_positives = json_data.get("positives", 0)
            num_total = json_data.get("total", 0)
            scan_date = json_data.get("scan_date", None)
            permalink = json_data.get("permalink", None)
            self.output("Message: %s" % verbose_msg)
            self.output("Scan ID: %s" % scan_id)
            self.output("Detection ratio: %s/%s" % (num_positives, num_total))
            self.output("Scan date: %s" % scan_date)
            self.output("Permalink: %s" % permalink)
        elif response_code == -2:
            # NOTE: This case is obsolete with API v3. The v3 API does not return
            # a separate "queued for analysis" state. This block is kept for
            # documentation purposes but will never be reached with v3 responses.
            # Requested item is still queued for analysis (v2 only)
            verbose_msg = json_data.get("verbose_msg", None)
            scan_id = json_data.get("scan_id", None)
            permalink = json_data.get("permalink", None)
            self.output("Message: %s" % verbose_msg)
            self.output("Scan ID: %s" % scan_id)
            self.output("Permalink: %s" % permalink)

        # Extract the information we need for the summary results
        num_positives = json_data.get("positives", 0)
        num_total = json_data.get("total", 0)
        permalink = json_data.get("permalink", "None")

        # record our time -- we use this to throttle our frequency
        os.environ['AUTOPKG_VIRUSTOTAL_LAST_RUN_TIME'] = str(int(time.time()))
        
        # Save summary result
        self.env["virus_total_analyzer_summary_result"] = {
            'summary_text': 'The following items were queried from the VirusTotal database:',
            'report_fields': [
                'name',
                'ratio',
                'permalink',
            ],
            'data': {
                'name': os.path.basename(input_path),
                'ratio': "%s/%s" % (num_positives, num_total),
                'permalink': permalink,
            }
        }


if __name__ == "__main__":
    processor = VirusTotalAnalyzer()
    processor.execute_shell()
