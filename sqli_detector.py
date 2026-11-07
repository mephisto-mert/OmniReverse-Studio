"""OmniReverse SQL Injection (SQLi) Static Analysis Engine (SAST)
Performs Abstract Syntax Tree (AST) taint tracking and sink-source analysis
to detect unparameterized SQL queries in Python, JavaScript, PHP, and Java.
"""

import ast
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Finding:
    file_path: str
    line_number: int
    sink: str
    vulnerable_snippet: str
    severity: str
    description: str
    remediation: str


class PythonSQLiVisitor(ast.NodeVisitor):
    """AST visitor to detect SQL injection sinks in Python source code."""

    SQL_SINKS = {
        "execute", "executemany", "raw", "raw_query", "query",
        "fetch_all", "fetch_one", "fetch_val"
    }

    SQL_KEYWORDS = re.compile(
        r"\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE|UNION\s+SELECT|WHERE|FROM)\b",
        re.IGNORECASE
    )

    def __init__(self, filename: str, source_lines: list[str]):
        self.filename = filename
        self.source_lines = source_lines
        self.findings: list[Finding] = []
        # Track variables assigned to tainted SQL strings
        self.tainted_vars: dict[str, tuple[int, str]] = {}

    def _get_line_snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def visit_Assign(self, node: ast.Assign):
        # Detect: query = f"SELECT * FROM users WHERE id = {user_id}"
        val = node.value
        is_sql = False
        val_lineno = getattr(val, "lineno", node.lineno)

        # 1. f-string
        if isinstance(val, ast.JoinedStr):
            # Check if any part is SQL
            for part in val.values:
                if isinstance(part, ast.Constant) and isinstance(part.value, str):
                    if self.SQL_KEYWORDS.search(part.value):
                        is_sql = True
                        break
            if is_sql:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_vars[target.id] = (val_lineno, "f-string")

        # 2. String concat (+)
        elif isinstance(val, ast.BinOp) and isinstance(val.op, ast.Add):
            snippet = self._get_line_snippet(val_lineno)
            if self.SQL_KEYWORDS.search(snippet):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_vars[target.id] = (val_lineno, "string concatenation (+)")

        # 3. % or .format()
        elif isinstance(val, ast.BinOp) and isinstance(val.op, ast.Mod):
            snippet = self._get_line_snippet(val_lineno)
            if self.SQL_KEYWORDS.search(snippet):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_vars[target.id] = (val_lineno, "% modulo formatting")

        elif isinstance(val, ast.Call) and isinstance(val.func, ast.Attribute) and val.func.attr == "format":
            snippet = self._get_line_snippet(val_lineno)
            if self.SQL_KEYWORDS.search(snippet):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_vars[target.id] = (val_lineno, ".format() formatting")

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id

        if func_name in self.SQL_SINKS and node.args:
            first_arg = node.args[0]
            lineno = node.lineno
            snippet = self._get_line_snippet(lineno)

            # Check 1: Direct f-string inside execute(f"SELECT...")
            if isinstance(first_arg, ast.JoinedStr):
                self.findings.append(Finding(
                    file_path=self.filename,
                    line_number=lineno,
                    sink=func_name,
                    vulnerable_snippet=snippet,
                    severity="CRITICAL",
                    description=f"`{func_name}()` çağrısı içinde f-string ile güvensiz SQL birleştirmesi tespit edildi.",
                    remediation="Sorguyu parametrelendirin: `cursor.execute('SELECT ... WHERE id = %s', (user_id,))`"
                ))

            # Check 2: Direct string concat inside execute("SELECT..." + user_input)
            elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Add):
                self.findings.append(Finding(
                    file_path=self.filename,
                    line_number=lineno,
                    sink=func_name,
                    vulnerable_snippet=snippet,
                    severity="CRITICAL",
                    description=f"`{func_name}()` çağrısı içinde '+' operatörüyle doğrudan string birleştirmesi yapılmış.",
                    remediation="Değişkenleri string ile toplamak yerine yer tutucu (placeholder) kullanın: `execute(sql, (param,))`"
                ))

            # Check 3: Direct .format() or % inside execute
            elif isinstance(first_arg, ast.Call) and isinstance(first_arg.func, ast.Attribute) and first_arg.func.attr == "format":
                self.findings.append(Finding(
                    file_path=self.filename,
                    line_number=lineno,
                    sink=func_name,
                    vulnerable_snippet=snippet,
                    severity="HIGH",
                    description=f"`{func_name}()` çağrısı içinde `.format()` metodu ile dinamik SQL üretilmiş.",
                    remediation="Format metodu yerine veritabanı sürücüsünün parametreli sorgu mekanizmasını kullanın."
                ))
            elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Mod):
                self.findings.append(Finding(
                    file_path=self.filename,
                    line_number=lineno,
                    sink=func_name,
                    vulnerable_snippet=snippet,
                    severity="HIGH",
                    description=f"`{func_name}()` çağrısı içinde `%` operatörü ile string formatlaması yapılmış.",
                    remediation="Yüzde (%) operatörü yerine prepared statement kullanın."
                ))

            # Check 4: Variable previously tainted by string formatting
            elif isinstance(first_arg, ast.Name) and first_arg.id in self.tainted_vars:
                assign_line, method = self.tainted_vars[first_arg.id]
                self.findings.append(Finding(
                    file_path=self.filename,
                    line_number=lineno,
                    sink=func_name,
                    vulnerable_snippet=f"{snippet} (Taint kaynağı: Satır {assign_line}, değişken '{first_arg.id}' [{method}])",
                    severity="CRITICAL",
                    description=f"`{first_arg.id}` değişkeni satır {assign_line}'de güvensiz `{method}` ile oluşturulup `{func_name}()` içine aktarılmış.",
                    remediation=f"'{first_arg.id}' değişkenine dinamik girdi gömmeyin; statik SQL şablonu hazırlayıp parametreleri tuple/dizi olarak geçirin."
                ))

        self.generic_visit(node)


def audit_python_code(code_str: str, filename: str = "snippet.py") -> list[Finding]:
    """Audits a Python source code string using AST."""
    source_lines = code_str.splitlines()
    try:
        tree = ast.parse(code_str)
        visitor = PythonSQLiVisitor(filename, source_lines)
        visitor.visit(tree)
        return visitor.findings
    except SyntaxError as e:
        # Fallback to regex if syntax error (e.g. partial snippet)
        return audit_generic_regex(code_str, filename)


def audit_generic_regex(code_str: str, filename: str) -> list[Finding]:
    """Pattern-based sink analysis for JavaScript, PHP, Java, and partial snippets."""
    findings = []
    lines = code_str.splitlines()

    # JS/Node.js template literal sink: db.query(`SELECT ... ${input}`)
    js_tpl_regex = re.compile(
        r"(?:db|pool|client|connection|sequelize)\.(?:query|execute)\s*\(\s*`[^`]*\b(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b[^`]*\$\{[^}]+\}",
        re.IGNORECASE
    )

    # Generic concatenation in query sink: .query("SELECT ... " + input)
    generic_concat_regex = re.compile(
        r"(?:query|execute|executeQuery|executeUpdate|raw)\s*\(\s*['\"][^'\"]*\b(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b[^'\"]*['\"]\s*\+",
        re.IGNORECASE
    )

    # PHP concatenation: mysql_query("... " . $input) — bounded quantifier (CWE-1333 ReDoS guard)
    php_concat_regex = re.compile(
        r"(?:mysqli_query|mysql_query|\$pdo->query|\$db->query)\s*\(\s*(?:['\"][^'\"]{0,500}|[^;\n]{0,500}?)\.\s*\$_(?:GET|POST|REQUEST|COOKIE)",
        re.IGNORECASE
    )

    for lineno, line in enumerate(lines, 1):
        if len(line) > 4096:
            continue
        if js_tpl_regex.search(line):
            findings.append(Finding(
                file_path=filename,
                line_number=lineno,
                sink="query/execute",
                vulnerable_snippet=line.strip(),
                severity="CRITICAL",
                description="JavaScript template literal (`${...}`) ile güvensiz SQL sorgusu birleştirilmiş.",
                remediation="Parametreli dizi kullanın: `db.query('SELECT ... WHERE id = $1', [id])`"
            ))
        elif php_concat_regex.search(line):
            findings.append(Finding(
                file_path=filename,
                line_number=lineno,
                sink="mysqli_query / PDO::query",
                vulnerable_snippet=line.strip(),
                severity="CRITICAL",
                description="PHP süperglobal girdisi ($_GET/$_POST) doğrudan SQL sorgusuyla birleştirilmiş.",
                remediation="PDO veya MySQLi Prepared Statement kullanın: `$stmt = $pdo->prepare('...'); $stmt->execute([$id]);`"
            ))
        elif generic_concat_regex.search(line):
            findings.append(Finding(
                file_path=filename,
                line_number=lineno,
                sink="query/execute",
                vulnerable_snippet=line.strip(),
                severity="HIGH",
                description="SQL sorgu fonksiyonu içinde '+' operatörüyle string birleştirme tespit edildi.",
                remediation="Parametreli sorgu (Prepared Statement) kullanarak girdileri parametre olarak iletin."
            ))

    return findings


def audit_target(target_path_or_code: str, is_snippet: bool = False, language: str = "auto") -> dict[str, Any]:
    """Audits a file, directory, or code snippet for SQL injection vulnerabilities."""
    all_findings: list[Finding] = []
    files_scanned = 0

    if is_snippet:
        findings = audit_python_code(target_path_or_code, "snippet.py")
        if not findings and language in ("auto", "javascript", "php", "java"):
            findings.extend(audit_generic_regex(target_path_or_code, "snippet"))
        all_findings.extend(findings)
        files_scanned = 1
    else:
        path = Path(target_path_or_code).resolve()
        if path.is_file():
            files_to_scan = [path]
        elif path.is_dir():
            excluded_dirs = {".git", "node_modules", "__pycache__", "winsdk", ".venv", "venv", ".ghidra_projects", "dist", "build"}
            files_to_scan = [
                p for p in path.rglob("*")
                if p.is_file()
                and p.suffix.lower() in (".py", ".js", ".ts", ".php", ".java")
                and not (excluded_dirs & set(p.parts))
                and p.stat().st_size <= 2 * 1024 * 1024
            ][:500]
        else:
            raise FileNotFoundError(f"Hedef dosya veya klasör bulunamadı: {target_path_or_code}")

        files_scanned = len(files_to_scan)
        for f in files_to_scan:
            try:
                code_text = f.read_text(encoding="utf-8", errors="ignore")
                if f.suffix.lower() == ".py":
                    findings = audit_python_code(code_text, str(f))
                else:
                    findings = audit_generic_regex(code_text, str(f))
                all_findings.extend(findings)
            except Exception:
                pass

    # Build Markdown Report
    lines = [
        "# 🛡️ OmniReverse SAST: SQL Injection (SQLi) Güvenlik Denetim Raporu",
        "",
        "## 1. Denetim Özeti",
        f"* **Taranan Dosya Sayısı:** `{files_scanned}`",
        f"* **Toplam Tespit Edilen Zafiyet:** `{len(all_findings)}`",
        f"* **Durum:** `{'🚨 ZAFİYET TESPİT EDİLDİ' if all_findings else '✅ TEMİZ (Açık Tespit Edilmedi)'}`",
        "",
    ]

    if all_findings:
        lines.extend([
            "## 2. Zafiyet Detayları ve Kanıtlar",
            "",
            "| # | Şiddet | Dosya | Satır | Sink | Açıklama |",
            "| :---: | :---: | :--- | :---: | :--- | :--- |",
        ])
        for idx, fnd in enumerate(all_findings, 1):
            short_path = Path(fnd.file_path).name if fnd.file_path != "snippet.py" else "snippet.py"
            lines.append(
                f"| {idx} | **{fnd.severity}** | `{short_path}` | Satır {fnd.line_number} | `{fnd.sink}` | {fnd.description} |"
            )

        lines.extend([
            "",
            "## 3. Kod Satırları ve Çözüm Önerileri (Remediation)",
            ""
        ])
        for idx, fnd in enumerate(all_findings, 1):
            lines.extend([
                f"### Zafiyet #{idx}: `{Path(fnd.file_path).name}` (Satır {fnd.line_number})",
                f"* **Güvensiz Kod:**",
                f"```python\n{fnd.vulnerable_snippet}\n```",
                f"* **Düzeltme Rehberi:**",
                f"> {fnd.remediation}",
                ""
            ])
    else:
        lines.extend([
            "## 2. Sonuç",
            "Taranan kaynak kodda dinamik string birleştirme ile veritabanı sink'ine aktarılan güvensiz SQL sorgusu tespit edilmedi.",
            "Tüm sorgular ya statik ya da parametrelendirilmiş (Prepared Statement) görünüyor."
        ])

    return {
        "files_scanned": files_scanned,
        "vulnerabilities_count": len(all_findings),
        "findings": [
            {
                "file": f.file_path,
                "line": f.line_number,
                "severity": f.severity,
                "sink": f.sink,
                "snippet": f.vulnerable_snippet,
                "description": f.description,
                "remediation": f.remediation
            }
            for f in all_findings
        ],
        "report_markdown": "\n".join(lines)
    }
