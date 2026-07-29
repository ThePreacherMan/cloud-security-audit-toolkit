"""Utilities for loading and validating cloud audit configuration files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class CloudDataError(ValueError):
    """Raised when cloud audit data is missing or invalid."""


REQUIRED_TOP_LEVEL_FIELDS = {
    "provider",
    "account_id",
    "environment",
    "resources",
}


def validate_cloud_data(data: dict[str, Any]) -> None:
    """Validate the minimum structure required for an audit."""

    missing_fields = REQUIRED_TOP_LEVEL_FIELDS - data.keys()

    if missing_fields:
        missing = ", ".join(sorted(missing_fields))
        raise CloudDataError(
            f"Cloud configuration is missing required fields: {missing}"
        )

    if not isinstance(data["resources"], list):
        raise CloudDataError(
            "The 'resources' field must contain a list of cloud resources."
        )

    if not data["provider"]:
        raise CloudDataError("The 'provider' field cannot be empty.")

    if not data["account_id"]:
        raise CloudDataError("The 'account_id' field cannot be empty.")

    if not data["environment"]:
        raise CloudDataError("The 'environment' field cannot be empty.")


def load_cloud_data(file_path: str | Path) -> dict[str, Any]:
    """Load and validate cloud configuration data from a JSON file."""

    path = Path(file_path)

    if not path.exists():
        raise CloudDataError(
            f"Cloud configuration file was not found: {path}"
        )

    if not path.is_file():
        raise CloudDataError(
            f"The supplied path is not a file: {path}"
        )

    try:
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except json.JSONDecodeError as error:
        raise CloudDataError(
            f"Invalid JSON in cloud configuration file: {error}"
        ) from error
    except OSError as error:
        raise CloudDataError(
            f"Unable to read cloud configuration file: {error}"
        ) from error

    if not isinstance(data, dict):
        raise CloudDataError(
            "The cloud configuration must be a JSON object."
        )

    validate_cloud_data(data)

    return data
