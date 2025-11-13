const EventEmitter = require('events');
const cron = require('node-cron');

/**
 * Scheduler - Automated scan scheduling and execution
 * Supports cron-based scheduling for regular vulnerability scans
 */
class Scheduler extends EventEmitter {
  constructor(database, proxyBackend) {
    super();
    this.db = database;
    this.proxyBackend = proxyBackend;
    this.schedules = new Map(); // Active schedules
    this.cronJobs = new Map(); // Cron job instances
    this.executionHistory = new Map(); // Execution history by schedule ID

    this.loadSchedules();
  }

  /**
   * Load saved schedules from database
   */
  loadSchedules() {
    try {
      const savedSchedules = this.db.getSetting('schedules');
      if (savedSchedules) {
        const schedules = JSON.parse(savedSchedules);
        schedules.forEach(schedule => {
          this.schedules.set(schedule.id, schedule);
          if (schedule.enabled) {
            this.startSchedule(schedule.id);
          }
        });
      }
    } catch (error) {
      console.error('Error loading schedules:', error);
    }
  }

  /**
   * Save schedules to database
   */
  saveSchedules() {
    const schedules = Array.from(this.schedules.values());
    this.db.setSetting('schedules', JSON.stringify(schedules));
  }

  /**
   * Create a new schedule
   */
  createSchedule(scheduleData) {
    const schedule = {
      id: scheduleData.id || this.generateScheduleId(),
      name: scheduleData.name,
      description: scheduleData.description || '',
      enabled: scheduleData.enabled !== false,
      cronExpression: scheduleData.cronExpression, // e.g., "0 2 * * *" for 2 AM daily
      type: scheduleData.type || 'scan', // scan, spider, macro
      config: scheduleData.config || {},
      projectId: scheduleData.projectId || null,
      notifications: scheduleData.notifications || {
        onStart: false,
        onComplete: true,
        onError: true,
        email: null,
        webhook: null
      },
      createdAt: Date.now(),
      updatedAt: Date.now(),
      lastRun: null,
      nextRun: null,
      runCount: 0
    };

    // Validate cron expression
    if (!cron.validate(schedule.cronExpression)) {
      throw new Error('Invalid cron expression');
    }

    this.schedules.set(schedule.id, schedule);
    this.saveSchedules();

    if (schedule.enabled) {
      this.startSchedule(schedule.id);
    }

    this.emit('schedule-created', schedule);

    return schedule;
  }

  /**
   * Update a schedule
   */
  updateSchedule(scheduleId, updates) {
    const schedule = this.schedules.get(scheduleId);
    if (!schedule) {
      throw new Error(`Schedule ${scheduleId} not found`);
    }

    // Stop existing cron job if running
    if (this.cronJobs.has(scheduleId)) {
      this.stopSchedule(scheduleId);
    }

    // Apply updates
    Object.assign(schedule, updates);
    schedule.updatedAt = Date.now();

    this.schedules.set(scheduleId, schedule);
    this.saveSchedules();

    // Restart if enabled
    if (schedule.enabled) {
      this.startSchedule(scheduleId);
    }

    this.emit('schedule-updated', schedule);

    return schedule;
  }

  /**
   * Delete a schedule
   */
  deleteSchedule(scheduleId) {
    if (this.cronJobs.has(scheduleId)) {
      this.stopSchedule(scheduleId);
    }

    this.schedules.delete(scheduleId);
    this.executionHistory.delete(scheduleId);
    this.saveSchedules();

    this.emit('schedule-deleted', scheduleId);
  }

  /**
   * Start a schedule
   */
  startSchedule(scheduleId) {
    const schedule = this.schedules.get(scheduleId);
    if (!schedule) {
      throw new Error(`Schedule ${scheduleId} not found`);
    }

    if (this.cronJobs.has(scheduleId)) {
      console.log(`Schedule ${scheduleId} is already running`);
      return;
    }

    const cronJob = cron.schedule(schedule.cronExpression, async () => {
      await this.executeSchedule(scheduleId);
    });

    this.cronJobs.set(scheduleId, cronJob);
    schedule.enabled = true;
    this.saveSchedules();

    console.log(`Started schedule: ${schedule.name}`);
    this.emit('schedule-started', schedule);
  }

  /**
   * Stop a schedule
   */
  stopSchedule(scheduleId) {
    const schedule = this.schedules.get(scheduleId);
    const cronJob = this.cronJobs.get(scheduleId);

    if (cronJob) {
      cronJob.stop();
      this.cronJobs.delete(scheduleId);
    }

    if (schedule) {
      schedule.enabled = false;
      this.saveSchedules();
    }

    console.log(`Stopped schedule: ${schedule?.name}`);
    this.emit('schedule-stopped', schedule);
  }

  /**
   * Execute a schedule
   */
  async executeSchedule(scheduleId) {
    const schedule = this.schedules.get(scheduleId);
    if (!schedule) {
      return;
    }

    const execution = {
      id: this.generateExecutionId(),
      scheduleId,
      scheduleName: schedule.name,
      startTime: Date.now(),
      endTime: null,
      status: 'running',
      results: null,
      error: null
    };

    // Add to execution history
    if (!this.executionHistory.has(scheduleId)) {
      this.executionHistory.set(scheduleId, []);
    }
    this.executionHistory.get(scheduleId).push(execution);

    // Update schedule
    schedule.lastRun = execution.startTime;
    schedule.runCount++;
    this.saveSchedules();

    this.emit('execution-started', execution);

    if (schedule.notifications.onStart) {
      this.sendNotification(schedule, 'started', execution);
    }

    try {
      let results;

      switch (schedule.type) {
        case 'scan':
          results = await this.executeScan(schedule);
          break;
        case 'spider':
          results = await this.executeSpider(schedule);
          break;
        case 'macro':
          results = await this.executeMacro(schedule);
          break;
        default:
          throw new Error(`Unknown schedule type: ${schedule.type}`);
      }

      execution.status = 'completed';
      execution.results = results;
      execution.endTime = Date.now();

      this.emit('execution-completed', execution);

      if (schedule.notifications.onComplete) {
        this.sendNotification(schedule, 'completed', execution);
      }

    } catch (error) {
      execution.status = 'failed';
      execution.error = error.message;
      execution.endTime = Date.now();

      this.emit('execution-failed', execution);

      if (schedule.notifications.onError) {
        this.sendNotification(schedule, 'error', execution);
      }

      console.error(`Schedule execution failed for ${schedule.name}:`, error);
    }

    // Keep only last 100 executions per schedule
    const history = this.executionHistory.get(scheduleId);
    if (history.length > 100) {
      this.executionHistory.set(scheduleId, history.slice(-100));
    }
  }

  /**
   * Execute scan
   */
  async executeScan(schedule) {
    const { Scanner } = require('../scanner');
    const scanner = new Scanner(schedule.config, this.db);

    return new Promise((resolve, reject) => {
      const results = {
        vulnerabilities: [],
        startTime: Date.now(),
        endTime: null
      };

      scanner.on('vulnerability-found', (vuln) => {
        results.vulnerabilities.push(vuln);
      });

      scanner.on('completed', () => {
        results.endTime = Date.now();
        resolve(results);
      });

      scanner.on('error', (error) => {
        reject(error);
      });

      // Start scan
      const urls = schedule.config.urls || [];
      const policy = schedule.config.policy || {};

      scanner.scan(urls, policy).catch(reject);

      // Timeout after 1 hour
      setTimeout(() => {
        scanner.stop();
        results.endTime = Date.now();
        resolve(results);
      }, 3600000);
    });
  }

  /**
   * Execute spider
   */
  async executeSpider(schedule) {
    const { Spider } = require('../spider');
    const spider = new Spider(schedule.config, this.db);

    return new Promise((resolve, reject) => {
      const results = {
        endpoints: [],
        startTime: Date.now(),
        endTime: null
      };

      spider.on('endpoint-discovered', (endpoint) => {
        results.endpoints.push(endpoint);
      });

      spider.on('completed', (stats) => {
        results.endTime = Date.now();
        results.stats = stats;
        resolve(results);
      });

      spider.on('error', (error) => {
        reject(error);
      });

      // Start spider
      const startUrls = schedule.config.startUrls || [];
      spider.start(startUrls).catch(reject);
    });
  }

  /**
   * Execute macro
   */
  async executeMacro(schedule) {
    const macroId = schedule.config.macroId;
    const variables = schedule.config.variables || {};

    const result = await this.proxyBackend.sessionHandler.executeMacro(macroId, variables);

    return {
      macroId,
      results: result.results,
      variables: result.variables
    };
  }

  /**
   * Send notification
   */
  async sendNotification(schedule, event, execution) {
    const message = this.formatNotificationMessage(schedule, event, execution);

    // Email notification
    if (schedule.notifications.email) {
      // TODO: Implement email sending
      console.log(`Email notification: ${message}`);
    }

    // Webhook notification
    if (schedule.notifications.webhook) {
      try {
        const axios = require('axios');
        await axios.post(schedule.notifications.webhook, {
          event,
          schedule: {
            id: schedule.id,
            name: schedule.name
          },
          execution: {
            id: execution.id,
            status: execution.status,
            startTime: execution.startTime,
            endTime: execution.endTime
          },
          message
        });
      } catch (error) {
        console.error('Webhook notification failed:', error);
      }
    }

    this.emit('notification-sent', { schedule, event, message });
  }

  /**
   * Format notification message
   */
  formatNotificationMessage(schedule, event, execution) {
    switch (event) {
      case 'started':
        return `Schedule "${schedule.name}" started execution`;
      case 'completed':
        return `Schedule "${schedule.name}" completed. Duration: ${execution.endTime - execution.startTime}ms`;
      case 'error':
        return `Schedule "${schedule.name}" failed: ${execution.error}`;
      default:
        return `Schedule "${schedule.name}" event: ${event}`;
    }
  }

  /**
   * Get all schedules
   */
  getSchedules(filters = {}) {
    let schedules = Array.from(this.schedules.values());

    if (filters.enabled !== undefined) {
      schedules = schedules.filter(s => s.enabled === filters.enabled);
    }

    if (filters.type) {
      schedules = schedules.filter(s => s.type === filters.type);
    }

    if (filters.projectId) {
      schedules = schedules.filter(s => s.projectId === filters.projectId);
    }

    return schedules.sort((a, b) => b.updatedAt - a.updatedAt);
  }

  /**
   * Get schedule by ID
   */
  getSchedule(scheduleId) {
    return this.schedules.get(scheduleId);
  }

  /**
   * Get execution history
   */
  getExecutionHistory(scheduleId, limit = 50) {
    const history = this.executionHistory.get(scheduleId) || [];
    return history.slice(-limit).reverse();
  }

  /**
   * Run schedule immediately (manual trigger)
   */
  async runNow(scheduleId) {
    const schedule = this.schedules.get(scheduleId);
    if (!schedule) {
      throw new Error(`Schedule ${scheduleId} not found`);
    }

    await this.executeSchedule(scheduleId);
  }

  /**
   * Generate schedule ID
   */
  generateScheduleId() {
    return `sched_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Generate execution ID
   */
  generateExecutionId() {
    return `exec_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Cleanup - stop all schedules
   */
  cleanup() {
    for (const [scheduleId] of this.cronJobs) {
      this.stopSchedule(scheduleId);
    }

    this.schedules.clear();
    this.cronJobs.clear();
    this.executionHistory.clear();
    this.removeAllListeners();
  }
}

module.exports = Scheduler;
