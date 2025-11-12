const fs = require('fs');
const path = require('path');
const { app } = require('electron');

class ConfigurationManager {
  constructor() {
    // Get user data directory
    this.configDir = path.join(app.getPath('userData'), 'profiles');
    this.currentProfile = 'default';

    // Ensure config directory exists
    if (!fs.existsSync(this.configDir)) {
      fs.mkdirSync(this.configDir, { recursive: true });
    }

    // Available packet fields for custom columns
    this.availableFields = [
      { id: 'no', label: 'Number', type: 'number' },
      { id: 'timestamp', label: 'Timestamp', type: 'string' },
      { id: 'relativeTime', label: 'Relative Time', type: 'string' },
      { id: 'source', label: 'Source Address', type: 'string' },
      { id: 'destination', label: 'Destination Address', type: 'string' },
      { id: 'srcPort', label: 'Source Port', type: 'number' },
      { id: 'dstPort', label: 'Destination Port', type: 'number' },
      { id: 'protocol', label: 'Protocol', type: 'string' },
      { id: 'length', label: 'Length', type: 'number' },
      { id: 'info', label: 'Info', type: 'string' },
      { id: 'raw.ethernet.src', label: 'Ethernet Source MAC', type: 'string', path: 'raw.ethernet.src' },
      { id: 'raw.ethernet.dst', label: 'Ethernet Dest MAC', type: 'string', path: 'raw.ethernet.dst' },
      { id: 'raw.ip.version', label: 'IP Version', type: 'number', path: 'raw.ip.version' },
      { id: 'raw.ip.ttl', label: 'TTL', type: 'number', path: 'raw.ip.ttl' },
      { id: 'raw.ip.protocol', label: 'IP Protocol Number', type: 'number', path: 'raw.ip.protocol' }
    ];

    // Default configuration
    this.defaultConfig = {
      name: 'default',
      displayFilters: [],
      bpfFilter: '',
      customColumns: [
        { id: 'no', label: 'No.', width: 80, visible: true },
        { id: 'timestamp', label: 'Time', width: 150, visible: true },
        { id: 'source', label: 'Source', width: 150, visible: true },
        { id: 'destination', label: 'Destination', width: 150, visible: true },
        { id: 'protocol', label: 'Protocol', width: 100, visible: true },
        { id: 'length', label: 'Length', width: 80, visible: true },
        { id: 'info', label: 'Info', width: 300, visible: true }
      ],
      colorRules: [
        { name: 'TCP Errors', filter: 'tcp.analysis.flags', bgColor: '#fca5a5', fgColor: '#000000' },
        { name: 'HTTP', filter: 'protocol:HTTP', bgColor: '#bfdbfe', fgColor: '#000000' },
        { name: 'DNS', filter: 'protocol:DNS', bgColor: '#c7d2fe', fgColor: '#000000' },
        { name: 'ICMP', filter: 'protocol:ICMP', bgColor: '#fef08a', fgColor: '#000000' }
      ],
      captureOptions: {
        promiscuous: true,
        monitor: false,
        snaplen: 65535,
        ringBuffer: false,
        maxFiles: 5,
        maxFileSize: 100 * 1024 * 1024
      },
      uiLayout: {
        packetListHeight: 50,
        showHexView: true,
        showSecurityAlerts: true,
        fontSize: 'medium'
      }
    };

    // Load or create default profile
    this.loadProfile('default');
  }

  getProfilePath(profileName) {
    return path.join(this.configDir, `${profileName}.json`);
  }

  loadProfile(profileName) {
    const profilePath = this.getProfilePath(profileName);

    try {
      if (fs.existsSync(profilePath)) {
        const data = fs.readFileSync(profilePath, 'utf8');
        this.config = JSON.parse(data);
        this.currentProfile = profileName;
        console.log(`Loaded profile: ${profileName}`);
        return this.config;
      } else {
        // Create default profile
        this.config = { ...this.defaultConfig, name: profileName };
        this.saveProfile(profileName);
        this.currentProfile = profileName;
        console.log(`Created default profile: ${profileName}`);
        return this.config;
      }
    } catch (error) {
      console.error(`Error loading profile ${profileName}:`, error);
      this.config = { ...this.defaultConfig, name: profileName };
      return this.config;
    }
  }

  saveProfile(profileName = this.currentProfile) {
    const profilePath = this.getProfilePath(profileName);

    try {
      this.config.name = profileName;
      fs.writeFileSync(profilePath, JSON.stringify(this.config, null, 2));
      console.log(`Saved profile: ${profileName}`);
      return true;
    } catch (error) {
      console.error(`Error saving profile ${profileName}:`, error);
      return false;
    }
  }

  listProfiles() {
    try {
      const files = fs.readdirSync(this.configDir);
      return files
        .filter(file => file.endsWith('.json'))
        .map(file => file.replace('.json', ''));
    } catch (error) {
      console.error('Error listing profiles:', error);
      return ['default'];
    }
  }

  deleteProfile(profileName) {
    if (profileName === 'default') {
      return { success: false, error: 'Cannot delete default profile' };
    }

    const profilePath = this.getProfilePath(profileName);

    try {
      if (fs.existsSync(profilePath)) {
        fs.unlinkSync(profilePath);

        // Switch to default if deleting current profile
        if (this.currentProfile === profileName) {
          this.loadProfile('default');
        }

        return { success: true };
      } else {
        return { success: false, error: 'Profile not found' };
      }
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  duplicateProfile(sourceName, newName) {
    const sourcePath = this.getProfilePath(sourceName);
    const newPath = this.getProfilePath(newName);

    try {
      if (fs.existsSync(newPath)) {
        return { success: false, error: 'Profile already exists' };
      }

      if (!fs.existsSync(sourcePath)) {
        return { success: false, error: 'Source profile not found' };
      }

      const data = fs.readFileSync(sourcePath, 'utf8');
      const config = JSON.parse(data);
      config.name = newName;

      fs.writeFileSync(newPath, JSON.stringify(config, null, 2));

      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  // Custom Columns Management
  getCustomColumns() {
    return this.config.customColumns || this.defaultConfig.customColumns;
  }

  setCustomColumns(columns) {
    this.config.customColumns = columns;
    this.saveProfile();
  }

  addCustomColumn(field, position = -1) {
    const columns = this.getCustomColumns();
    const fieldInfo = this.availableFields.find(f => f.id === field.id);

    if (!fieldInfo) {
      return { success: false, error: 'Invalid field' };
    }

    const newColumn = {
      id: field.id,
      label: field.label || fieldInfo.label,
      width: field.width || 150,
      visible: true,
      path: fieldInfo.path || field.id
    };

    if (position >= 0 && position < columns.length) {
      columns.splice(position, 0, newColumn);
    } else {
      columns.push(newColumn);
    }

    this.config.customColumns = columns;
    this.saveProfile();

    return { success: true, columns };
  }

  removeCustomColumn(columnId) {
    const columns = this.getCustomColumns();
    const index = columns.findIndex(col => col.id === columnId);

    if (index === -1) {
      return { success: false, error: 'Column not found' };
    }

    columns.splice(index, 1);
    this.config.customColumns = columns;
    this.saveProfile();

    return { success: true, columns };
  }

  reorderColumns(fromIndex, toIndex) {
    const columns = this.getCustomColumns();

    if (fromIndex < 0 || fromIndex >= columns.length || toIndex < 0 || toIndex >= columns.length) {
      return { success: false, error: 'Invalid indices' };
    }

    const [removed] = columns.splice(fromIndex, 1);
    columns.splice(toIndex, 0, removed);

    this.config.customColumns = columns;
    this.saveProfile();

    return { success: true, columns };
  }

  updateColumnWidth(columnId, width) {
    const columns = this.getCustomColumns();
    const column = columns.find(col => col.id === columnId);

    if (!column) {
      return { success: false, error: 'Column not found' };
    }

    column.width = width;
    this.saveProfile();

    return { success: true };
  }

  toggleColumnVisibility(columnId) {
    const columns = this.getCustomColumns();
    const column = columns.find(col => col.id === columnId);

    if (!column) {
      return { success: false, error: 'Column not found' };
    }

    column.visible = !column.visible;
    this.saveProfile();

    return { success: true, visible: column.visible };
  }

  // Display Filters Management
  getDisplayFilters() {
    return this.config.displayFilters || [];
  }

  addDisplayFilter(filter) {
    const filters = this.getDisplayFilters();

    // Avoid duplicates
    if (!filters.find(f => f.name === filter.name)) {
      filters.push({
        name: filter.name,
        filter: filter.filter,
        enabled: filter.enabled !== false
      });

      this.config.displayFilters = filters;
      this.saveProfile();
    }

    return { success: true, filters };
  }

  removeDisplayFilter(filterName) {
    const filters = this.getDisplayFilters();
    const index = filters.findIndex(f => f.name === filterName);

    if (index !== -1) {
      filters.splice(index, 1);
      this.config.displayFilters = filters;
      this.saveProfile();
    }

    return { success: true, filters };
  }

  // BPF Filter
  setBPFFilter(filter) {
    this.config.bpfFilter = filter;
    this.saveProfile();
    return { success: true };
  }

  getBPFFilter() {
    return this.config.bpfFilter || '';
  }

  // Color Rules
  getColorRules() {
    return this.config.colorRules || this.defaultConfig.colorRules;
  }

  addColorRule(rule) {
    const rules = this.getColorRules();
    rules.push(rule);
    this.config.colorRules = rules;
    this.saveProfile();
    return { success: true, rules };
  }

  removeColorRule(ruleName) {
    const rules = this.getColorRules();
    const index = rules.findIndex(r => r.name === ruleName);

    if (index !== -1) {
      rules.splice(index, 1);
      this.config.colorRules = rules;
      this.saveProfile();
    }

    return { success: true, rules };
  }

  // Capture Options
  getCaptureOptions() {
    return this.config.captureOptions || this.defaultConfig.captureOptions;
  }

  setCaptureOptions(options) {
    this.config.captureOptions = { ...this.config.captureOptions, ...options };
    this.saveProfile();
    return { success: true, options: this.config.captureOptions };
  }

  // UI Layout
  getUILayout() {
    return this.config.uiLayout || this.defaultConfig.uiLayout;
  }

  setUILayout(layout) {
    this.config.uiLayout = { ...this.config.uiLayout, ...layout };
    this.saveProfile();
    return { success: true, layout: this.config.uiLayout };
  }

  // Get current configuration
  getCurrentConfig() {
    return {
      profile: this.currentProfile,
      config: this.config
    };
  }

  // Get available fields for custom columns
  getAvailableFields() {
    return this.availableFields;
  }

  // Export configuration
  exportConfig(exportPath) {
    try {
      fs.writeFileSync(exportPath, JSON.stringify(this.config, null, 2));
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  // Import configuration
  importConfig(importPath, profileName) {
    try {
      const data = fs.readFileSync(importPath, 'utf8');
      const config = JSON.parse(data);

      config.name = profileName;
      this.config = config;
      this.saveProfile(profileName);
      this.loadProfile(profileName);

      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
}

module.exports = ConfigurationManager;
