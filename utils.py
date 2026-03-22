import io
from ipaddress import IPv4Address
from pathlib import Path
from typing import Iterable

import pandas as pd


def styled_output(message: str, header: str = "") -> None:
	"""Print a message in a simple styled output block."""
	message_text = str(message)
	message_lines = message_text.splitlines() or [""]
	header_text = f"# {header}" if header else ""
	width = max(max(len(line) for line in message_lines), len(header_text), 3)
	border = "=" * width

	print(border)
	if header_text:
		print(header_text)
	print(message_text)
	print(border)


def load_siem_dataset(csv_path: str | Path, encoding: str = "utf-8") -> pd.DataFrame:
	"""Load the SIEM dataset with a consistent pandas configuration."""
	return pd.read_csv(Path(csv_path), encoding=encoding, low_memory=False)


def dataframe_info_text(df: pd.DataFrame) -> str:
	"""Return the output of DataFrame.info() as plain text."""
	buffer = io.StringIO()
	df.info(buf=buffer)
	return buffer.getvalue()


def null_percentage_summary(df: pd.DataFrame) -> pd.DataFrame:
	"""Build a sorted summary of missing values by column."""
	summary = pd.DataFrame({"nulos": df.isna().sum()})
	summary["porcentaje"] = (summary["nulos"] / len(df) * 100).round(2)
	return summary.sort_values(["porcentaje", "nulos"], ascending=False)


def top_value_counts(
	df: pd.DataFrame,
	column: str,
	*,
	dropna: bool = False,
	top_n: int | None = None,
) -> pd.DataFrame:
	"""Return the most frequent values of a column as a DataFrame."""
	counts = df[column].value_counts(dropna=dropna)
	if top_n is not None:
		counts = counts.head(top_n)
	return counts.rename("conteo").to_frame()


def normalize_text_columns(df: pd.DataFrame, columns: Iterable[str]) -> pd.DataFrame:
	"""Strip and title-case the requested text columns while preserving missing values."""
	normalized = df.copy()
	for column in columns:
		normalized[column] = (
			normalized[column]
			.astype("string")
			.str.strip()
			.str.title()
			.replace({"Nan": pd.NA, "<Na>": pd.NA, "<NA>": pd.NA})
		)
	return normalized


def is_valid_ipv4(value: object) -> bool:
	"""Validate whether a value contains a syntactically correct IPv4 address."""
	if pd.isna(value):
		return False
	try:
		IPv4Address(str(value).strip())
		return True
	except ValueError:
		return False


def invalid_ipv4_examples(series: pd.Series, limit: int | None = None) -> list[str]:
	"""Return unique invalid IPv4 values found in a Series."""
	invalid_values = series.dropna().astype(str)
	invalid_values = invalid_values[~invalid_values.map(is_valid_ipv4)]
	unique_invalid_values = pd.Index(invalid_values).drop_duplicates().tolist()
	if limit is not None:
		return unique_invalid_values[:limit]
	return unique_invalid_values

