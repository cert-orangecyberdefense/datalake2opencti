import datetime
import json
import logging
import os
import re
import sys
import time

import stix2
import yaml
from datalake import AtomType, Datalake, Output
from pycti import (
    STIX_EXT_OCTI_SCO,
    Note,
    OpenCTIConnectorHelper,
    OpenCTIStix2,
    get_config_variable,
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
    curated_labels = [
        label for label in curated_labels if label is not None and len(label) > 0
    ]
    return curated_labels


def _get_ranged_score(score: int):
    if score == 100:
        return 90
    return (score // 10) * 10


def _generate_markdown_table(data):
    markdown_str = "## Threat scores\n"
    markdown_str += (
        "| DDoS | Fraud | Hack | Leak | Malware | Phishing | Scam | Scan | Spam |\n"
    )
    markdown_str += (
        "|------|-------|------|------|---------|----------|------|------|------|\n"
    )

    threat_scores = data.get("x_datalake_score", {})
    ddos = threat_scores.get("ddos", "-")
    fraud = threat_scores.get("fraud", "-")
    hack = threat_scores.get("hack", "-")
    leak = threat_scores.get("leak", "-")
    malware = threat_scores.get("malware", "-")
    phishing = threat_scores.get("phishing", "-")
    scam = threat_scores.get("scam", "-")
    scan = threat_scores.get("scan", "-")
    spam = threat_scores.get("spam", "-")

    markdown_str += f"| {ddos} | {fraud} | {hack} | {leak} | {malware} | {phishing} | {scam} | {scan} | {spam} |\n"
    markdown_str += "## Threat intelligence sources\n"
    markdown_str += (
        "| source_id | count | first_seen | last_updated | min_depth | max_depth |\n"
    )
    markdown_str += (
        "|-----------|-------|------------|--------------|-----------|-----------|\n"
    )

    threat_sources = data.get("x_datalake_sources", [])

    # Sort the threat_sources by 'last_updated' in descending order
    threat_sources.sort(key=lambda x: x.get("last_updated", ""), reverse=True)

    for source in threat_sources:
        source_id = source.get("source_id", "-")
        count = source.get("count", "-")
        first_seen = source.get("first_seen", "-")
        if first_seen != "-":
            # Format 'first_seen' to 'YYYY-MM-DD'
            first_seen = datetime.datetime.fromisoformat(
                first_seen.rstrip("Z")
            ).strftime("%Y-%m-%d %H:%M")
        last_updated = source.get("last_updated", "-")
        if last_updated != "-":
            # Format 'last_updated' to 'YYYY-MM-DD'
            last_updated = datetime.datetime.fromisoformat(
                last_updated.rstrip("Z")
            ).strftime("%Y-%m-%d %H:%M")
        min_depth = source.get("min_depth", "-")
        max_depth = source.get("max_depth", "-")

        markdown_str += f"| {source_id} | {count} | {first_seen} | {last_updated} | {min_depth} | {max_depth} |\n"

    return markdown_str


def get_atom_type(observable_type: str):
    mapping = {
        "Autonomous-System": AtomType.AS,
        "Domain-Name": AtomType.DOMAIN,
        "Email-Addr": AtomType.EMAIL,
        "IPv4-Addr": AtomType.IP,
        "IPv6-Addr": AtomType.IP,
        "Phone-Number": AtomType.PHONE_NUMBER,
        "Url": AtomType.URL,
        "X509-Certificate": AtomType.CERTIFICATE,
        "StixFile": AtomType.FILE,
        "Cryptocurrency-Wallet": AtomType.CRYPTO,
    }
    return mapping.get(observable_type, None)


def validate_scope(value: str) -> str:
    available_values = {
        "ipv4-addr": "IPv4-Addr",
        "ipv6-addr": "IPv6-Addr",
        "url": "URL",
        "email-addr": "Email-Addr",
        "phone-number": "Phone-Number",
        "x509-certificate": "X509-Certificate",
        "cryptocurrency-wallet": "Cryptocurrency-Wallet",
        "autonomous-system": "Autonomous-System",
        "domain-name": "Domain-Name",
        "stixfile": "StixFile",
    }
    scope_splitted = [scope.strip().lower() for scope in value.split(",")]
    valid_scope = [
        available_values[scope] for scope in scope_splitted if scope in available_values
    ]

    if not valid_scope:
        raise ValueError(
            f"No valid scopes found. Allowed values are: {available_values}."
        )
    scope_string = ",".join(valid_scope)

    return scope_string


class OrangeCyberdefenseEnrichment:
    def __init__(self):
        config_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "config.yml"
        )
        config = (
            yaml.load(open(config_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_path)
            else {}
        )

        defaults = {
            "connector": {
                "name": "Orange Cyberdefense CTI Enrichment",
                "scope": "IPv4-Addr,IPv6-Addr,Domain-Name,URL,Email-Addr,Autonomous-System,X509-Certificate,Cryptocurrency-Wallet,StixFile,Phone-Number",
                "auto": False,
                "log_level": "info",
            }
        }

        config["connector"] = {**defaults["connector"], **config.get("connector", {})}

        config["connector"]["scope"] = validate_scope(config["connector"]["scope"])
        config["connector"]["type"] = "INTERNAL_ENRICHMENT"

        self.helper = OpenCTIConnectorHelper(config)

        self.ocd_enrich_datalake_token = get_config_variable(
            "OCD_ENRICH_DATALAKE_TOKEN", ["ocd_enrich", "datalake_token"], config
        )

        self.ocd_enrich_datalake_env = get_config_variable(
            "OCD_ENRICH_DATALAKE_ENV",
            ["ocd_enrich", "datalake_env"],
            config,
            default="prod",
        )

        self.ocd_enrich_add_tags_as_labels = get_config_variable(
            "OCD_ENRICH_ADD_TAGS_AS_LABELS",
            ["ocd_enrich", "add_tags_as_labels"],
            config,
            default=True,
        )

        self.ocd_enrich_add_scores_as_labels = get_config_variable(
            "OCD_ENRICH_ADD_SCORES_AS_LABELS",
            ["ocd_enrich", "add_scores_as_labels"],
            config,
            default=True,
        )

        self.ocd_enrich_threat_actor_as_intrusion_set = get_config_variable(
            "OCD_ENRICH_THREAT_ACTOR_AS_INTRUSION_SET",
            ["ocd_enrich", "threat_actor_as_intrusion_set"],
            config,
            default=True,
        )

        self.ocd_enrich_add_score = get_config_variable(
            "OCD_ENRICH_ADD_SCORE", ["ocd_enrich", "add_score"], config, default=True
        )

        self.ocd_enrich_add_extref = get_config_variable(
            "OCD_ENRICH_ADD_EXTREF", ["ocd_enrich", "add_extref"], config, default=True
        )

        self.ocd_enrich_add_summary = get_config_variable(
            "OCD_ENRICH_ADD_SUMMARY",
            ["ocd_enrich", "add_summary"],
            config,
            default=True,
        )

        self.ocd_enrich_add_related = get_config_variable(
            "OCD_ENRICH_ADD_RELATED",
            ["ocd_enrich", "add_related"],
            config,
            default=True,
        )

        self.max_tlp = get_config_variable(
            "OCD_ENRICH_MAX_TLP", ["ocd_enrich", "max_tlp"], config, default="TLP:AMBER"
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
            longterm_token=self.ocd_enrich_datalake_token,
            env=self.ocd_enrich_datalake_env,
        )

    def _process_object(self, object):

        dict_label_to_object_marking_refs = {
            "tlp:clear": [stix2.TLP_WHITE.get("id")],
            "tlp:white": [stix2.TLP_WHITE.get("id")],
            "tlp:green": [stix2.TLP_GREEN.get("id")],
            "tlp:amber": [stix2.TLP_AMBER.get("id"), self.marking["standard_id"]],
            "tlp:red": [stix2.TLP_RED.get("id"), self.marking["standard_id"]],
        }
        if "labels" in object:
            for label in object["labels"]:
                if label in dict_label_to_object_marking_refs.keys():
                    object["object_marking_refs"] = dict_label_to_object_marking_refs[
                        label
                    ]
        if "labels" in object and self.ocd_enrich_add_tags_as_labels:
            object["labels"] = _curate_labels(object["labels"])
        else:
            object["labels"] = []
        if "confidence" not in object:
            object["confidence"] = self.helper.connect_confidence_level
        if "x_datalake_score" in object:
            scores = list(object["x_datalake_score"].values())
            if len(scores) > 0:
                object["x_opencti_score"] = max(scores)

        if "created_by_ref" not in object:
            object["created_by_ref"] = self.identity["standard_id"]
        if "external_references" in object:
            external_references = []
            for external_reference in object["external_references"]:
                if "url" in external_reference:
                    external_reference["url"] = external_reference["url"].replace(
                        "api/v3/mrti/threats", "gui/threat"
                    )
                    external_references.append(external_reference)
                else:
                    external_references.append(external_reference)
            object["external_references"] = external_references

        # Type specific operations
        if (
            object["type"] == "threat-actor"
            and self.ocd_enrich_threat_actor_as_intrusion_set
        ):
            object["type"] = "intrusion-set"
            object["id"] = object["id"].replace("threat-actor", "intrusion-set")
        if object["type"] == "sector":
            object["type"] = "identity"
            object["identity_class"] = "class"
            object["id"] = object["id"].replace("sector", "identity")
        if object["type"] == "relationship":
            object["source_ref"] = object["source_ref"].replace("sector", "identity")
            object["target_ref"] = object["target_ref"].replace("sector", "identity")
            if self.ocd_enrich_threat_actor_as_intrusion_set:
                object["source_ref"] = object["source_ref"].replace(
                    "threat-actor", "intrusion-set"
                )
                object["target_ref"] = object["target_ref"].replace(
                    "threat-actor", "intrusion-set"
                )
        if object["type"] == "indicator" and self.ocd_enrich_add_scores_as_labels:
            threat_scores = object.get("x_datalake_score", {})
            for threat_type, score in threat_scores.items():
                ranged_score = _get_ranged_score(score)
                new_label = f"dtl_{threat_type}_{ranged_score}"
                if "labels" not in object:
                    object["labels"] = []
                object["labels"].append(new_label)
        return object

    def _generate_observable_note(self, indicator_object, stix_entity):
        creation_date = indicator_object.get("created", {})
        technical_md = _generate_markdown_table(indicator_object)
        note_stix = stix2.Note(
            id=Note.generate_id(creation_date, technical_md),
            confidence=self.helper.connect_confidence_level,
            abstract="OCD-CERT Datalake additional informations",
            content=technical_md,
            created=creation_date,
            modified=indicator_object["modified"],
            created_by_ref=self.identity["standard_id"],
            object_marking_refs=[self.marking["standard_id"]],
            object_refs=[stix_entity["id"], indicator_object["id"]],
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
            self.helper.log_info(
                f"Not enriching {value} because {tlp} is higher than {self.max_tlp}"
            )
            return

        data = self.dtl.Threats.lookup(
            atom_value=value,
            atom_type=get_atom_type(observable["entity_type"]),
            output=Output.STIX,
        )

        if "threat_found" in data:
            self.helper.log_info(f"No threat found for {value}")
            return

        self.helper.log_info(f"Match found for {value}")

        related_objects = []
        for object in data["objects"]:
            if object["type"] == "indicator":
                indicator_object = object
            related_objects.append(self._process_object(object))

        labels = []
        max_score = -1

        threat_scores = indicator_object.get("x_datalake_score", {})
        for threat_type, score in threat_scores.items():
            ranged_score = _get_ranged_score(score)
            new_label = f"dtl_{threat_type}_{ranged_score}"
            labels.append(new_label)
            if score > max_score:
                max_score = score

        if self.ocd_enrich_add_score and max_score != -1:
            OpenCTIStix2.put_attribute_in_extension(
                stix_entity, STIX_EXT_OCTI_SCO, "score", max_score
            )

        if self.ocd_enrich_add_scores_as_labels:
            for label in labels:
                OpenCTIStix2.put_attribute_in_extension(
                    stix_entity,
                    STIX_EXT_OCTI_SCO,
                    "labels",
                    label,
                    True,
                )

        if self.ocd_enrich_add_tags_as_labels:
            labels = _curate_labels(indicator_object.get("labels", []))
            for label in labels:
                OpenCTIStix2.put_attribute_in_extension(
                    stix_entity,
                    STIX_EXT_OCTI_SCO,
                    "labels",
                    label,
                    True,
                )

        if self.ocd_enrich_add_extref:
            for external_reference in indicator_object.get("external_references", []):
                if "url" in external_reference:
                    try:
                        external_reference["url"] = external_reference["url"].replace(
                            "api/v3/mrti/threats", "gui/threat"
                        )
                        ext_ref = self.helper.api.external_reference.create(
                            source_name=external_reference.get(
                                "source_name", "Orange Cyberdefense"
                            ),
                            url=external_reference["url"],
                            external_id=external_reference.get("external_id", None),
                        )
                        self.helper.api.stix_cyber_observable.add_external_reference(
                            id=stix_entity["id"],
                            external_reference_id=ext_ref["id"],
                        )
                    except Exception as e:
                        self.helper.log_error(
                            f"Unable to create external reference: {str(e)}"
                        )

        if self.ocd_enrich_add_summary:
            try:
                note_stix = self._generate_observable_note(
                    indicator_object, stix_entity
                )
                stix_objects.append(json.loads(note_stix.serialize()))
            except Exception as e:
                self.helper.log_error(f"Unable to create enrichment note: {str(e)}")

        if self.ocd_enrich_add_related:
            stix_objects.extend(related_objects)

        relationship = stix2.Relationship(
            relationship_type="based-on",
            source_ref=indicator_object["id"],
            target_ref=stix_entity["id"],
            confidence=self.helper.connect_confidence_level,
            created_by_ref=self.identity["standard_id"],
            object_marking_refs=[self.marking["standard_id"]],
        )
        stix_objects.append(json.loads(relationship.serialize()))

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
