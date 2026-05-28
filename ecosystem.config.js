// PM2 Ecosystem config for nethunter-TUI background services
// Usage:
//   pm2 start ecosystem.config.js          # start all services
//   pm2 start ecosystem.config.js --only honeypot  # start just honeypot
//   pm2 status
//   pm2 logs
//   pm2 stop ecosystem.config.js
//   pm2 save && pm2 startup   # persist across reboots

module.exports = {
  apps: [
    {
      name: "honeypot",
      script: "bin/honeypot-daemon",
      args: "--instance primary",
      interpreter: "python3",
      cwd: __dirname,
      watch: false,
      autorestart: true,
      max_restarts: 10,
      min_uptime: "10s",
      log_date_format: "YYYY-MM-DD HH:mm:ss Z",
      error_file: "logs/honeypot-error.log",
      out_file: "logs/honeypot-out.log",
      merge_logs: true,
      pid_file: "logs/honeypot.pid",
    },
    {
      name: "honeypot-shadow",
      script: "bin/honeypot-daemon",
      args: "--instance shadow",
      interpreter: "python3",
      cwd: __dirname,
      watch: false,
      autorestart: true,
      max_restarts: 10,
      min_uptime: "10s",
      log_date_format: "YYYY-MM-DD HH:mm:ss Z",
      error_file: "logs/honeypot-shadow-error.log",
      out_file: "logs/honeypot-shadow-out.log",
      merge_logs: true,
      pid_file: "logs/honeypot-shadow.pid",
    },
    {
      name: "vpn-logger",
      script: "bin/vpn-logger-daemon",
      interpreter: "python3",
      cwd: __dirname,
      watch: false,
      autorestart: true,
      max_restarts: 5,
      min_uptime: "10s",
      log_date_format: "YYYY-MM-DD HH:mm:ss Z",
      error_file: "logs/vpn-logger-error.log",
      out_file: "logs/vpn-logger-out.log",
      merge_logs: true,
      pid_file: "logs/vpn-logger.pid",
    },
    {
      name: "nethunter-tui",
      script: "run.py",
      interpreter: "python3",
      cwd: __dirname,
      watch: false,
      autorestart: false, /* TUI by měl ruční restart */
      log_date_format: "YYYY-MM-DD HH:mm:ss Z",
      error_file: "logs/tui-error.log",
      out_file: "logs/tui-out.log",
      merge_logs: true,
    },
  ],
};
