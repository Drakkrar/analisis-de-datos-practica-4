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


def parse_mixed_datetime(series: pd.Series, dayfirst: bool = False) -> pd.Series:
	"""Parse a Series with mixed datetime formats while preserving invalid entries as NaT."""
	return pd.to_datetime(series, format="mixed", dayfirst=dayfirst, errors="coerce")


def datetime_parse_failures(original: pd.Series, parsed: pd.Series) -> pd.Series:
	"""Return original non-null values that could not be parsed into datetimes."""
	return original[original.notna() & parsed.isna()]


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


def convert_nullable_integer_columns(df: pd.DataFrame, columns: Iterable[str]) -> pd.DataFrame:
	"""Convert selected columns to nullable integers using pandas Int64 dtype."""
	converted = df.copy()
	for column in columns:
		converted[column] = pd.to_numeric(converted[column], errors="coerce").astype("Int64")
	return converted


def convert_boolean_columns(df: pd.DataFrame, columns: Iterable[str]) -> pd.DataFrame:
	"""Convert common boolean-like values to pandas' nullable boolean dtype."""
	converted = df.copy()
	boolean_map = {
		True: True,
		False: False,
		"true": True,
		"false": False,
		"1": True,
		"0": False,
		"yes": True,
		"no": False,
	}
	for column in columns:
		normalized = converted[column]
		if normalized.dtype == "object" or str(normalized.dtype).startswith("string"):
			normalized = normalized.astype("string").str.strip().str.lower()
		converted[column] = normalized.replace(boolean_map).astype("boolean")
	return converted


def is_valid_ipv4(value: object) -> bool:
	"""Validate whether a value contains a syntactically correct IPv4 address."""
	if pd.isna(value):
		return False
	try:
		IPv4Address(str(value).strip())
		return True
	except ValueError:
		return False


def invalid_ipv4_mask(series: pd.Series) -> pd.Series:
	"""Return a boolean mask marking invalid IPv4 values in a Series."""
	return ~series.map(is_valid_ipv4)


def invalid_ipv4_examples(series: pd.Series, limit: int | None = None) -> list[str]:
	"""Return unique invalid IPv4 values found in a Series."""
	invalid_values = series.dropna().astype(str)
	invalid_values = invalid_values[~invalid_values.map(is_valid_ipv4)]
	unique_invalid_values = pd.Index(invalid_values).drop_duplicates().tolist()
	if limit is not None:
		return unique_invalid_values[:limit]
	return unique_invalid_values


def false_positive_aggressive_action_mask(
	df: pd.DataFrame,
	*,
	fp_column: str = "falso_positivo",
	action_column: str = "accion_tomada",
) -> pd.Series:
	"""Flag false positives that ended in an aggressive containment action."""
	aggressive_actions = {"Bloqueado", "Cuarentenado"}
	return df[fp_column].fillna(False) & df[action_column].isin(aggressive_actions)


def resolved_without_timestamp_mask(
	df: pd.DataFrame,
	*,
	resolved_column: str = "resuelto",
	resolution_column: str = "timestamp_resolucion",
) -> pd.Series:
	"""Flag rows marked as resolved but missing a resolution timestamp."""
	return df[resolved_column].fillna(False) & df[resolution_column].isna()


def resolution_before_event_mask(
	df: pd.DataFrame,
	*,
	event_column: str = "timestamp_evento",
	resolution_column: str = "timestamp_resolucion",
) -> pd.Series:
	"""Flag rows whose resolution timestamp is earlier than the event timestamp."""
	return df[resolution_column].notna() & df[event_column].notna() & (df[resolution_column] < df[event_column])


def calculate_response_time_minutes(
	df: pd.DataFrame,
	*,
	event_column: str = "timestamp_evento",
	resolution_column: str = "timestamp_resolucion",
) -> pd.Series:
	"""Compute response time in minutes from event and resolution timestamps."""
	return ((df[resolution_column] - df[event_column]).dt.total_seconds() / 60).round().astype("Int64")


def response_time_inconsistency_mask(
	reported: pd.Series,
	calculated: pd.Series,
	*,
	tolerance_minutes: int = 30,
) -> pd.Series:
	"""Flag rows whose reported response time differs from the calculated one beyond tolerance."""
	return reported.notna() & calculated.notna() & (reported.sub(calculated).abs() > tolerance_minutes)


def sla_limit_series(
	severity: pd.Series,
	*,
	sla_map: dict[str, int] | None = None,
) -> pd.Series:
	"""Map severity labels to their SLA limit in minutes."""
	if sla_map is None:
		sla_map = {"Crítica": 60, "Alta": 240, "Media": 480, "Baja": 1440}
	return severity.map(sla_map).astype("Int64")


def sla_violation_mask(response_minutes: pd.Series, sla_limits: pd.Series) -> pd.Series:
	"""Flag rows whose response time exceeds the mapped SLA threshold."""
	return response_minutes.notna() & sla_limits.notna() & (response_minutes > sla_limits)


def same_source_destination_ip_mask(
	df: pd.DataFrame,
	*,
	source_column: str = "ip_origen",
	destination_column: str = "ip_destino",
) -> pd.Series:
	"""Flag rows where source and destination IPs are identical."""
	return df[source_column].notna() & df[destination_column].notna() & (df[source_column] == df[destination_column])


def successful_login_blocked_mask(
	df: pd.DataFrame,
	*,
	event_type_column: str = "tipo_evento",
	action_column: str = "accion_tomada",
) -> pd.Series:
	"""Flag rows where a successful login contradicts a blocked action."""
	return df[event_type_column].eq("Login Exitoso") & df[action_column].eq("Bloqueado")


def critical_false_positive_unresolved_mask(
	df: pd.DataFrame,
	*,
	fp_column: str = "falso_positivo",
	severity_column: str = "severidad",
	resolved_column: str = "resuelto",
) -> pd.Series:
	"""Flag suspicious rows marked as critical false positives that remain unresolved."""
	return df[fp_column].fillna(False) & df[severity_column].eq("Crítica") & ~df[resolved_column].fillna(False)


def remaining_nulls_summary(df: pd.DataFrame) -> pd.DataFrame:
	"""Return only columns that still contain missing values."""
	remaining = df.isna().sum().rename("nulos").to_frame()
	return remaining.loc[remaining["nulos"] > 0].sort_values("nulos", ascending=False)


def false_positive_rate_by_event(
	df: pd.DataFrame,
	*,
	event_type_column: str = "tipo_evento",
	fp_column: str = "falso_positivo",
) -> pd.DataFrame:
	"""Summarize false-positive rate and volume by event type."""
	summary = (
		df.groupby(event_type_column)[fp_column]
		.agg(["mean", "count"])
		.rename(columns={"mean": "tasa_fp", "count": "total"})
	)
	summary["tasa_fp"] = (summary["tasa_fp"] * 100).round(2)
	return summary.sort_values(["tasa_fp", "total"], ascending=[False, False])


def unresolved_critical_by_os(
	df: pd.DataFrame,
	*,
	severity_column: str = "severidad",
	resolved_column: str = "resuelto",
	os_column: str = "sistema_operativo",
) -> pd.Series:
	"""Count unresolved critical events by operating system."""
	mask = df[severity_column].eq("Crítica") & ~df[resolved_column].fillna(False)
	return (
		df.loc[mask, os_column]
		.fillna("Desconocido")
		.value_counts()
	)

