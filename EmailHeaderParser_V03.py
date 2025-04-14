import re
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, scrolledtext
import email
from email.header import decode_header
import os
import requests
import ipaddress

class IPAnalyzer:
    def __init__(self):
        self.ip_cache = {}

    def extract_ips(self, text):
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        return re.findall(ip_pattern, text)

    def get_ip_info(self, ip):
        if ip in self.ip_cache:
            return self.ip_cache[ip]

        try:
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
            response.raise_for_status()  # Raises exception for bad status codes
            data = response.json()
            if data['status'] == 'success':
                info = f"Location: {data.get('city', 'N/A')}, {data.get('country', 'N/A')}"
                self.ip_cache[ip] = info
                return info
        except requests.RequestException as e:
            return f"Geolocation failed: {str(e)}"
        except ValueError as e:
            return f"JSON parsing failed: {str(e)}"
        return "Location information not available"

class EmailHeaderDecoderGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Email Header Decoder")
        self.root.geometry("800x600")
        self.ip_analyzer = IPAnalyzer()
        self.create_widgets()

    def create_widgets(self):
        # Create buttons frame
        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=10)

        # Add buttons
        self.open_button = tk.Button(button_frame, text="Open Header File", command=self.open_file)
        self.open_button.pack(side=tk.LEFT, padx=5)

        self.clear_button = tk.Button(button_frame, text="Clear", command=self.clear_text)
        self.clear_button.pack(side=tk.LEFT, padx=5)

        self.save_button = tk.Button(button_frame, text="Save Analysis", command=self.save_analysis)
        self.save_button.pack(side=tk.LEFT, padx=5)

        # Add search frame
        search_frame = tk.Frame(self.root)
        search_frame.pack(pady=5)
        
        self.search_var = tk.StringVar()
        self.search_entry = tk.Entry(search_frame, textvariable=self.search_var)
        self.search_entry.pack(side=tk.LEFT, padx=5)
        
        self.search_button = tk.Button(search_frame, text="Search", command=self.search_text)
        self.search_button.pack(side=tk.LEFT)

        # Create text area
        self.text_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=80, height=30)
        self.text_area.pack(padx=10, pady=10, expand=True, fill='both')

        # Add status bar
        self.status_label = tk.Label(self.root, text="", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X)

        # Configure tags
        self.text_area.tag_configure('search', background='yellow')
        self.text_area.tag_configure('suspicious', foreground='red')
        self.text_area.tag_configure('safe', foreground='green')

        # Add search binding
        self.search_var.trace('w', lambda *args: self.search_text())

    def update_status(self, message):
        self.status_label.config(text=message)
        self.root.update()

    def decode_header_value(self, header_value):
        decoded_parts = []
        for part, charset in decode_header(header_value):
            if isinstance(part, bytes):
                try:
                    decoded_part = part.decode(charset if charset else 'utf-8', errors='replace')
                except:
                    decoded_part = part.decode('utf-8', errors='replace')
            else:
                decoded_part = part
            decoded_parts.append(decoded_part)
        return ' '.join(decoded_parts)

    def highlight_suspicious_headers(self, msg):
        suspicious_patterns = {
            'Received': r'(?i)(unknown|spam|reject)',
            'X-Spam-Status': r'(?i)(yes|high)',
            'X-Spam-Score': r'(\d+\.?\d*)',
            'Return-Path': r'(?i)(anonymous|spam|temp)',
            'Reply-To': r'(?i)(different from from field)'
        }
        
        highlights = []
        for header, value in msg.items():
            decoded_value = self.decode_header_value(value)
            if header in suspicious_patterns:
                if re.search(suspicious_patterns[header], decoded_value):
                    highlights.append((header, 'suspicious'))
                else:
                    highlights.append((header, 'safe'))
        return highlights

    def analyze_ip_addresses(self, content):
        ips = self.ip_analyzer.extract_ips(content)
        
        analysis = ["\n=== IP Analysis ==="]
        seen_ips = set()
        
        for ip in ips:
            if ip not in seen_ips:
                seen_ips.add(ip)
                try:
                    if ipaddress.ip_address(ip).is_private:
                        analysis.append(f"{ip}: Private IP Address")
                    else:
                        info = self.ip_analyzer.get_ip_info(ip)
                        analysis.append(f"{ip}: {info}")
                except ValueError:
                    continue
        
        return '\n'.join(analysis)

    def validate_headers(self, msg):
        validation_results = ["\n=== Header Validation ==="]
        
        essential_headers = ['From', 'To', 'Date', 'Subject']
        for header in essential_headers:
            if header in msg:
                validation_results.append(f"✓ {header} header present")
            else:
                validation_results.append(f"⨯ Missing {header} header")
        
        try:
            date_str = msg.get('Date', '')
            email.utils.parsedate_to_datetime(date_str)
            validation_results.append("✓ Date format is valid")
        except:
            validation_results.append("⨯ Invalid date format")
        
        message_id = msg.get('Message-ID', '')
        if message_id and '@' in message_id:
            validation_results.append("✓ Message-ID format appears valid")
        else:
            validation_results.append("⨯ Invalid or missing Message-ID")
        
        return '\n'.join(validation_results)

    def analyze_security_headers(self, msg):
        security_results = ["\n=== Security Analysis ==="]
        
        spf = msg.get('Received-SPF', 'Not Found')
        security_results.append(f"SPF Record: {spf}")
        
        dkim = msg.get('DKIM-Signature', 'Not Found')
        security_results.append(f"DKIM: {'Present' if dkim != 'Not Found' else 'Not Found'}")
        
        dmarc = msg.get('DMARC-Status', 'Not Found')
        security_results.append(f"DMARC: {dmarc}")
        
        return '\n'.join(security_results)

    def get_basic_headers(self, msg):
        decoded_headers = ["=== Raw Headers ==="]
        for header, value in msg.items():
            decoded_value = self.decode_header_value(value)
            decoded_headers.append(f"{header}: {decoded_value}")
        return '\n'.join(decoded_headers)

    def display_with_highlighting(self, content, highlights):
        lines = content.split('\n')
        for line in lines:
            for header, tag in highlights:
                if line.startswith(header):
                    self.text_area.insert(tk.END, line + '\n', tag)
                    break
            else:
                self.text_area.insert(tk.END, line + '\n')

    def parse_headers(self, content):
        try:
            self.update_status("Analyzing headers...")
            msg = email.message_from_string(content)
            
            self.text_area.delete(1.0, tk.END)
            
            highlights = self.highlight_suspicious_headers(msg)
            
            full_analysis = (
                self.get_basic_headers(msg) +
                self.analyze_security_headers(msg) +
                self.analyze_ip_addresses(content) +
                self.validate_headers(msg)
            )
            
            self.display_with_highlighting(full_analysis, highlights)
            self.update_status("Analysis complete!")
        except Exception as e:
            self.update_status(f"Error during analysis: {str(e)}")

    def open_file(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = file.read()
                self.parse_headers(content)
            except Exception as e:
                self.text_area.delete(1.0, tk.END)
                self.text_area.insert(tk.END, f"Error reading file: {str(e)}")

    def save_analysis(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as file:
                    file.write(self.text_area.get(1.0, tk.END))
                self.update_status("Analysis saved successfully!")
            except Exception as e:
                self.update_status(f"Error saving file: {str(e)}")

    def search_text(self):
        search_term = self.search_var.get().lower()
        self.text_area.tag_remove('search', '1.0', tk.END)
        
        if search_term:
            pos = '1.0'
            while True:
                pos = self.text_area.search(search_term, pos, tk.END, nocase=True)
                if not pos:
                    break
                end_pos = f"{pos}+{len(search_term)}c"
                self.text_area.tag_add('search', pos, end_pos)
                pos = end_pos

    def clear_text(self):
        self.text_area.delete(1.0, tk.END)
        self.update_status("")

def main():
    root = tk.Tk()
    app = EmailHeaderDecoderGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()