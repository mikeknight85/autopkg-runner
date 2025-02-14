#!/usr/local/autopkg/python

# BSD-3-Clause
# Copyright (c) Facebook, Inc. and its affiliates.
# Copyright (c) tig <https://6fx.eu/>.
# Copyright (c) Gusto, Inc.
#
# Modified for Azure DevOps and Teams webhook by almenscorner.io
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import os
import sys
import json
import plistlib
import requests
import subprocess
from pathlib import Path
from optparse import OptionParser

DEBUG = os.environ.get("DEBUG", False)
TEAMS_WEBHOOK = os.environ.get("TEAMS_WEBHOOK")
OVERRIDES_DIR = os.environ.get("OVERRIDES_DIR")
RECIPE_TO_RUN = os.environ.get("RECIPE", None)

class Recipe(object):
    def __init__(self, path):
        self.path = os.path.join(OVERRIDES_DIR, path)
        self.error = False
        self.results = {}
        self.updated = False
        self.verified = None

        self._keys = None
        self._has_run = False

    @property
    def plist(self):
        if self._keys is None:
            with open(self.path, "rb") as f:
                self._keys = plistlib.load(f)

        return self._keys

    @property
    def updated_version(self):
        if not self.results or not "imported" in self.results or self.results["imported"] == []:
            return None
        return self.results["imported"][0]["version"].strip().replace(" ", "")

    @property
    def name(self):
        return self.plist["Input"]["NAME"]

    @property
    def appID(self):
        if not self.results or not "imported" in self.results or self.results["imported"] == []:
            return False
        return self.results["imported"][0]["appID"].strip().replace(" ", "")
    
    @property
    def installed_as_managed(self):
        if not self.results or not "imported" in self.results or self.results["imported"] == []:
            return False
        return self.results["imported"][0]["installed_as_managed"].strip().replace(" ", "")
    
    @property
    def ignore_app_version(self):
        if not self.results or not "imported" in self.results or self.results["imported"] == []:
            return False
        return self.results["imported"][0]["ignore_app_version"].strip().replace(" ", "")

    def verify_trust_info(self):
        cmd = ["/usr/local/bin/autopkg",
               "verify-trust-info", self.path, "-vvv"]
        cmd = " ".join(cmd)

        if DEBUG:
            print("Running " + str(cmd))

        p = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True
        )
        (output, err) = p.communicate()
        p_status = p.wait()
        if p_status == 0:
            self.verified = True
        else:
            err = err.decode()
            self.results["message"] = err
            self.verified = False
        return self.verified

    def update_trust_info(self):
        cmd = ["/usr/local/bin/autopkg", "update-trust-info", self.path]
        cmd = " ".join(cmd)

        if DEBUG:
            print("Running " + str(cmd))

        # Fail loudly if this exits 0
        try:
            subprocess.check_call(cmd, shell=True)
        except subprocess.CalledProcessError as e:
            print(e.stderr)
            raise e

    def _parse_report(self, report):
        with open(report, "rb") as f:
            report_data = plistlib.load(f)

        failed_items = report_data.get("failures", [])
        imported_items = []
        if report_data["summary_results"]:
            # This means something happened
            munki_results = report_data["summary_results"].get(
                "munki_importer_summary_result", {}
            )
            imported_items.extend(munki_results.get("data_rows", []))

        return {"imported": imported_items, "failed": failed_items}

    def run(self):
        if self.verified == False:
            self.error = True
            self.results["failed"] = True
            self.results["imported"] = ""
        else:
            report = "/tmp/autopkg.plist"
            if not os.path.isfile(report):
                # Letting autopkg create them has led to errors on github runners
                Path(report).touch()

            try:
                cmd = [
                    "/usr/local/bin/autopkg",
                    "run",
                    self.path,
                    "-k",
                    "MUNKI_REPO_PLUGIN='SimpleMDMRepo'",
                    "-k",
                    "MUNKI_REPO=''",
                    "-k",
                    "extract_icon=True",
                    "-v",
                    "--post",
                    "io.github.hjuutilainen.VirusTotalAnalyzer/VirusTotalAnalyzer",
                    "--report-plist",
                    report,
                ]
                cmd = " ".join(cmd)
                if DEBUG:
                    print("Running " + str(cmd))

                subprocess.check_call(cmd, shell=True)

            except subprocess.CalledProcessError as e:
                self.error = True

            self._has_run = True
            self.results = self._parse_report(report)
            if not self.results["failed"] and not self.error and self.updated_version:
                self.updated = True

        return self.results
        

### Recipe handling
def handle_recipe(recipe, opts):
    if not opts.disable_verification:
        recipe.verify_trust_info()
    if recipe.verified in (True, None):
        recipe.run()
    return recipe


def parse_recipes(recipes):
    recipe_list = []
    ## Added this section so that we can run individual recipes
    if RECIPE_TO_RUN:
        for recipe in recipes:
            ext = os.path.splitext(recipe)[1]
            if ext != ".recipe":
                recipe_list.append(recipe + ".recipe")
            else:
                recipe_list.append(recipe)
    else:
        ext = os.path.splitext(recipes)[1]
        if ext == ".json":
            parser = json.load
        elif ext == ".plist":
            parser = plistlib.load
        else:
            print(
                f'Invalid run list extension "{ ext }" (expected plist or json)')
            sys.exit(1)

        with open(recipes, "rb") as f:
            recipe_list = parser(f)

    return map(Recipe, recipe_list)


def teams_alert(recipe, opts):
    if opts.debug:
        print("Debug: skipping Teams notification - debug is enabled!")
        return

    if TEAMS_WEBHOOK is None:
        print("Skipping Teams notification - webhook is missing!")
        return

    if not recipe.verified:
        task_title = f"{ recipe.name } failed trust verification"
        task_description = recipe.results["message"]
    elif recipe.error:
        task_title = f"Failed to import { recipe.name }"
        if not recipe.results["failed"]:
            task_description = "Unknown error"
        else:
            task_description = ("Error: {} \r \r" "Traceback: {} \r \r").format(
                recipe.results["failed"][0]["message"],
                recipe.results["failed"][0]["traceback"],
            )

            if "No releases found for repo" in task_description:
                # Just no updates
                return
    elif recipe.updated:
        task_title = "Imported %s %s" % (
            recipe.name, str(recipe.updated_version))
        task_description = (
        )
    else:
        # Also no updates
        return

    data = json.dumps(
        {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "contentUrl": 'null',
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.0",
                        "body": [
                                {
                                    "type": "Container",
                                    "id": "fbcee869-2754-287d-bb37-145a4ccd750b",
                                    "padding": "Default",
                                    "spacing": "None",
                                    "items": [
                                            {
                                                "type": "Container",
                                                "id": "7fb0970d-5b65-6f0a-81ec-7464fd54ec7c",
                                                "padding": "None",
                                                "items": [
                                                    {
                                                        "type": "TextBlock",
                                                        "id": "44906797-222f-9fe2-0b7a-e3ee21c6e380",
                                                        "text": task_title,
                                                        "wrap": True,
                                                        "weight": "Bolder",
                                                        "size": "Large"
                                                    }
                                                ]
                                            },
                                        {
                                                "type": "Container",
                                                "id": "085f14f7-9a8a-7b49-f5e5-62faff004585",
                                                "padding": "None",
                                                "items": [
                                                    {
                                                        "type": "TextBlock",
                                                        "id": "f7abdf1a-3cce-2159-28ef-f2f362ec937e",
                                                        "text": task_description,
                                                        "wrap": True
                                                    }
                                                ],
                                                "separator": True
                                            },
                                    ],
                                    "style": "emphasis"
                                }
                        ],
                        "padding": "None"
                    }
                }
            ]
        }
    )
    
    if "failed" not in task_title:
        result = json.loads(data)
        data=json.dumps(result)
        
    response = requests.post(
        TEAMS_WEBHOOK,
        data
    )
    
    if response.status_code != 200:
        raise ValueError(
            "Request to Teams returned an error %s, the response is:\n%s"
            % (response.status_code, response.text)
        )


def main():
    parser = OptionParser(description="Wrap AutoPkg with git support.")
    parser.add_option(
        "-l", "--list", help="Path to a plist or JSON list of recipe names."
    )
    parser.add_option(
        "-d",
        "--debug",
        action="store_true",
        help="Disables sending Teams alerts and adds more verbosity to output.",
    )
    parser.add_option(
        "-v",
        "--disable_verification",
        action="store_true",
        help="Disables recipe verification.",
    )

    (opts, _) = parser.parse_args()

    global DEBUG
    DEBUG = bool(DEBUG or opts.debug)

    failures = []

    recipes = RECIPE_TO_RUN.split(
        ", ") if RECIPE_TO_RUN else opts.list if opts.list else None
    if recipes is None:
        print("Recipe --list or RECIPE_TO_RUN not provided!")
        sys.exit(1)
    recipes = parse_recipes(recipes)
    for recipe in recipes:
        handle_recipe(recipe, opts)
        teams_alert(recipe, opts)
        if not opts.disable_verification:
            if not recipe.verified:
                failures.append(recipe)
    if not opts.disable_verification:
        if failures:
            title = " ".join([f"{recipe.name}" for recipe in failures])
            lines = [f"{recipe.results['message']}\n" for recipe in failures]
            with open("pull_request_title", "a+") as title_file:
                title_file.write(f"Update trust for {title}")
            with open("pull_request_body", "a+") as body_file:
                body_file.writelines(lines)

if __name__ == "__main__":
    main()
