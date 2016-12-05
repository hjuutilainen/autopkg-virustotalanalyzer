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
DEFAULT_SLEEP = 15
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

    def fetch_content(self, url, headers=None, form_parameters=None, data_parameters=None, curl_options=None):
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
        :returns: content as string
        """

        try:
            cmd = [self.env['CURL_PATH'], '--location']
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
            if proc.returncode:
                raise ProcessorError(
                    'Could not retrieve URL %s: %s' % (url, stderr))
        except OSError:
            raise ProcessorError('Could not retrieve URL: %s' % url)

        return data

    def submit_file(self, file_path, api_key):
        """Submit a file to VirusTotal for scanning

        :param file_path: Path to a file to upload
        :param api_key: API key to use
        :returns: JSON response
        """
        url = "https://www.virustotal.com/vtapi/v2/file/scan/upload_url"

        # Get the upload URL
        parameters = {"apikey": api_key}
        f = self.fetch_content(url, None, None, parameters, ["-G"])
        try:
            json_data = json.loads(f)
        except (ValueError, KeyError, TypeError) as e:
            self.output("Response was: %s" % f)
            self.output("JSON format error: %s" % e)
            json_data = json.loads(
                '{"response_code": 999, "verbose_msg": "Requesting upload URL failed..."}')
            return json_data

        upload_url = json_data.get('upload_url', None)
        if upload_url is None:
            return None

        # Upload the file
        file_path_for_post = "@%s" % file_path
        parameters = {"file": file_path_for_post, "apikey": api_key}
        f = self.fetch_content(upload_url, None, parameters)
        try:
            json_data = json.loads(f)
        except (ValueError, KeyError, TypeError) as e:
            self.output("Response was: %s" % f)
            self.output("JSON format error: %s" % e)
            json_data = json.loads(
                '{"response_code": 999, "verbose_msg": "Request failed, perhaps rate-limited..."}')

        # print json.dumps(json_data, sort_keys=True, indent=4)
        return json_data

    def report_for_hash(self, file_hash, api_key):
        """Request a VirusTotal report for a hash

        :param file_hash: md5, sha1 or sha256 hash
        :param api_key: API key to use
        :returns: JSON response
        """
        url = "https://www.virustotal.com/vtapi/v2/file/report"
        parameters = {"resource": file_hash, "apikey": api_key}
        f = self.fetch_content(url, None, parameters)
        try:
            json_data = json.loads(f)
        except (ValueError, KeyError, TypeError) as e:
            self.output("JSON response was: %s" % f)
            self.output("JSON format error: %s" % e)
            json_data = json.loads(
                '{"response_code": 999, "verbose_msg": "Request failed, perhaps rate-limited..."}')

        # print json.dumps(json_data, sort_keys=True, indent=4)
        return json_data

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
            # Requested item is still queued for analysis
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
