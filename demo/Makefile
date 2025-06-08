.PHONY: run run-enhanced scan view-report clean help

# Run the original demo
run:
	python3 mcp_security_demo.py

# Run the enhanced security demo
run-enhanced:
	python3 mcp_security_demo_enhanced.py

# Run a security scan and generate report
scan:
	python3 scan_report.py

# View the latest scan report
view-report:
	python3 report_viewer.py

# Clean up any temporary files
clean:
	rm -f *.log
	rm -f *.pyc
	rm -rf __pycache__

# Run the original demo with detailed logging
run-verbose:
	PYTHONPATH=.. python3 mcp_security_demo.py --log-level=DEBUG

# Run all demos in sequence
demo-all: run run-enhanced scan view-report

# Help target
help:
	@echo "MCP Security Guardian Demo Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  run           - Run the original demo"
	@echo "  run-enhanced  - Run the enhanced security demo"
	@echo "  scan          - Run security scan and generate report"
	@echo "  view-report   - View the latest scan report"
	@echo "  demo-all      - Run all demos in sequence"
	@echo "  run-verbose   - Run the original demo with detailed logging"
	@echo "  clean         - Clean up temporary files"
	@echo "  help          - Show this help message"