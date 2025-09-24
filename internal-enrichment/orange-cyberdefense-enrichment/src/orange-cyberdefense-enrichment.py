import json
import logging
import os
import time
import datetime
import sys
import re

import yaml
import stix2

from datalake import Datalake
from pycti import (
    STIX_EXT_OCTI_SCO,
    OpenCTIConnectorHelper,
    OpenCTIStix2,
    get_config_variable,
    Note,
)


def _curate_labels(labels):
    curated_labels = []
    for label in labels:
        if "tlp:" in label:
            continue
        label_value = label
        if '="' in label:
            label_value_split = label.split('="')
            label_value = label_value_split[1][:-1].strip()
        elif ":" in label:
            label_value_split = label.split(":")
            label_value = label_value_split[1].strip()
        if label_value.isdigit():
            if ":" in label:
                label_value_split = label.split(":")
                label_value = label_value_split[1].strip()
            else:
                label_value = label
        if '="' in label_value:
            label_value = label_value.replace('="', "-")[:-1]
        label_value = re.sub(r"\s+", "_", label_value.strip().lower())

        curated_labels.append(label_value)
    curated_labels = [label for label in curated_labels if label is not None and len(label) > 0]
    return curated_labels


def _get_ranged_score(score: int):
    if score == 100:
        return 90
    return (score // 10) * 10


def _generate_markdown_table(data):
    markdown_str = "## Threat scores\n"
    markdown_str += "| DDoS | Fraud | Hack | Leak | Malware | Phishing | Scam | Scan | Spam |\n"
    markdown_str += "|------|-------|------|------|---------|----------|------|------|------|\n"

    threat_scores = data.get("scores", [])
    ddos = fraud = hack = leak = malware = phishing = scam = scan = spam = "-"
    for score in threat_scores:
        if score["threat_type"] == "ddos":
            ddos = score["score"]["risk"]
        if score["threat_type"] == "fraud":
            fraud = score["score"]["risk"]
        if score["threat_type"] == "hack":
            hack = score["score"]["risk"]
        if score["threat_type"] == "leak":
            leak = score["score"]["risk"]
        if score["threat_type"] == "malware":
            malware = score["score"]["risk"]
        if score["threat_type"] == "phishing":
            phishing = score["score"]["risk"]
        if score["threat_type"] == "scam":
            scam = score["score"]["risk"]
        if score["threat_type"] == "scan":
            scan = score["score"]["risk"]
        if score["threat_type"] == "spam":
            spam = score["score"]["risk"]

    markdown_str += f"| {ddos} | {fraud} | {hack} | {leak} | {malware} | {phishing} | {scam} | {scan} | {spam} |\n"
    markdown_str += "## Threat intelligence sources\n"
    markdown_str += "| source_id | count | first_seen | last_updated | min_depth | max_depth |\n"
    markdown_str += "|-----------|-------|------------|--------------|-----------|-----------|\n"

    threat_sources = data.get("sources", [])

    # Sort the threat_sources by 'last_updated' in descending order
    threat_sources.sort(key=lambda x: x.get("last_updated", ""), reverse=True)

    for source in threat_sources:
        source_id = source.get("source_id", "-")
        count = source.get("count", "-")
        first_seen = source.get("first_seen", "-")
        if first_seen != "-":
            # Format 'first_seen' to 'YYYY-MM-DD'
            first_seen = datetime.datetime.fromisoformat(first_seen.rstrip("Z")).strftime(
                "%Y-%m-%d %H:%M"
            )
        last_updated = source.get("last_updated", "-")
        if last_updated != "-":
            # Format 'last_updated' to 'YYYY-MM-DD'
            last_updated = datetime.datetime.fromisoformat(last_updated.rstrip("Z")).strftime(
                "%Y-%m-%d %H:%M"
            )
        min_depth = source.get("min_depth", "-")
        max_depth = source.get("max_depth", "-")

        markdown_str += f"| {source_id} | {count} | {first_seen} | {last_updated} | {min_depth} | {max_depth} |\n"

    return markdown_str


class OrangeCyberdefenseEnrichment:
    def __init__(self):
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yml")
        config = (
            yaml.load(open(config_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_path)
            else {}
        )

        self.helper = OpenCTIConnectorHelper(config)

        self.datalake_token = get_config_variable(
            "OCD_ENRICH_DATALAKE_TOKEN", ["ocd", "ocd_enrich_datalake_token"], config
        )

        self.datalake_env = get_config_variable(
            "OCD_DATALAKE_ENV", ["ocd", "ocd_datalake_env"], config
        )

        self.ocd_enrich_add_labels = get_config_variable(
            "OCD_ENRICH_ADD_LABELS", ["ocd", "ocd_enrich_add_labels"], config
        )

        self.ocd_enrich_add_score = get_config_variable(
            "OCD_ENRICH_ADD_SCORE", ["ocd", "ocd_enrich_add_score"], config
        )

        self.ocd_enrich_add_extref = get_config_variable(
            "OCD_ENRICH_ADD_EXTREF", ["ocd", "ocd_enrich_add_extref"], config
        )

        self.ocd_enrich_add_summary = get_config_variable(
            "OCD_ENRICH_ADD_SUMMARY", ["ocd", "ocd_enrich_add_summary"], config
        )

        self.ocd_enrich_add_related = get_config_variable(
            "OCD_ENRICH_ADD_RELATED", ["ocd", "ocd_enrich_add_related"], config
        )

        self.max_tlp = get_config_variable(
            "OCD_ENRICH_MAX_TLP", ["ocd", "ocd_enrich_max_tlp"], config
        )

        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="Orange Cyberdefense",
            description="""Orange Cyberdefense is the expert cybersecurity business unit of the Orange Group,
            providing consulting, solutions and services to organizations around the globe.""",
        )
        self.marking = self.helper.api.marking_definition.create(
            definition_type="COMMERCIAL",
            definition="ORANGE CYBERDEFENSE",
            x_opencti_order=99,
            x_opencti_color="#ff7900",
        )

        self.dtl = Datalake(
            longterm_token=self.datalake_token,
            env=self.datalake_env,
        )

    def _generate_observable_note(self, datalake_data: dict, stix_entity: dict):
        technical_md = _generate_markdown_table(datalake_data)
        now = datetime.datetime.now(datetime.timezone.utc)

        note_stix = stix2.Note(
            id=Note.generate_id(now, technical_md),
            confidence=self.helper.connect_confidence_level,
            abstract="Datalake enrichment summary",
            content=technical_md,
            created=now,
            modified=now,
            created_by_ref=self.identity["standard_id"],
            object_marking_refs=[self.marking["standard_id"]],
            object_refs=[stix_entity["id"]],
        )

        return note_stix

    def _process_message(self, data: dict):
        observable = data["enrichment_entity"]
        value = observable["observable_value"]

        stix_objects = data["stix_objects"]
        stix_entity = data["stix_entity"]

        tlp = "TLP:CLEAR"
        for marking_definition in observable.get("objectMarking", []):
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError("Do not send any data, TLP of the observable is greater than MAX TLP")

        data = self.dtl.Threats.lookup(value)

        labels = []
        max_score = 0
        for score in data["scores"]:
            threat_type = score["threat_type"]
            threat_score = score["score"]["risk"]
            ranged_score = _get_ranged_score(threat_score)
            label = f"dtl_{threat_type}_{ranged_score}"
            labels.append(label)
            if threat_score > max_score:
                max_score = threat_score

        if self.ocd_enrich_add_score:
            OpenCTIStix2.put_attribute_in_extension(
                stix_entity, STIX_EXT_OCTI_SCO, "score", max_score
            )

        tags = [tag["name"] for tag in data["tags"]]

        if self.ocd_enrich_add_labels:
            labels.extend(_curate_labels(tags))
            for label in labels:
                OpenCTIStix2.put_attribute_in_extension(
                    stix_entity,
                    STIX_EXT_OCTI_SCO,
                    "labels",
                    label,
                    True,
                )

        if self.ocd_enrich_add_extref:
            try:
                external_reference = self.helper.api.external_reference.create(
                    source_name="Datalake",
                    url=f"https://ti2.extranet.mrti-center.com/gui/threat/{data['hashkey']}",
                )
                self.helper.api.stix_cyber_observable.add_external_reference(
                    id=stix_entity["id"],
                    external_reference_id=external_reference["id"],
                )
            except Exception as e:
                self.helper.log_error(f"Unable to create external reference: {str(e)}")

        if self.ocd_enrich_add_summary:
            try:
                note_stix = self._generate_observable_note(data, stix_entity)
                stix_objects.append(json.loads(note_stix.serialize()))
            except Exception as e:
                self.helper.log_error(f"Unable to create enrichment note: {e}")

        serialized_bundle = self.helper.stix2_create_bundle(stix_objects)
        self.helper.send_stix2_bundle(serialized_bundle)

    def run(self):
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    try:
        connector = OrangeCyberdefenseEnrichment()
        connector.run()
    except Exception as e:
        logging.error(str(e))
        time.sleep(10)
        sys.exit(1)
