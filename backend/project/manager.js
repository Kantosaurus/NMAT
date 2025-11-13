const fs = require('fs');
const path = require('path');
const { app } = require('electron');

/**
 * Project Manager - Handle project files and scan configurations
 * Provides reproducible scan configurations and multi-tenant project support
 */
class ProjectManager {
  constructor(database) {
    this.db = database;
    this.projectsDir = path.join(app.getPath('userData'), 'projects');
    this.currentProject = null;

    // Ensure projects directory exists
    if (!fs.existsSync(this.projectsDir)) {
      fs.mkdirSync(this.projectsDir, { recursive: true });
    }
  }

  /**
   * Create a new project
   */
  createProject(projectData) {
    const project = {
      id: projectData.id || this.generateProjectId(),
      name: projectData.name,
      description: projectData.description || '',
      createdAt: Date.now(),
      updatedAt: Date.now(),
      owner: projectData.owner || 'default',
      team: projectData.team || [],
      config: {
        scope: projectData.scope || [],
        scanPolicies: projectData.scanPolicies || [],
        sessionRules: projectData.sessionRules || [],
        macros: projectData.macros || [],
        collaboratorConfig: projectData.collaboratorConfig || null,
        proxySettings: projectData.proxySettings || {},
        spiderConfig: projectData.spiderConfig || {},
        scannerConfig: projectData.scannerConfig || {},
        intruderConfig: projectData.intruderConfig || {}
      },
      metadata: {
        tags: projectData.tags || [],
        priority: projectData.priority || 'medium',
        compliance: projectData.compliance || []
      }
    };

    // Save project file
    const projectPath = path.join(this.projectsDir, `${project.id}.json`);
    fs.writeFileSync(projectPath, JSON.stringify(project, null, 2));

    // Save to database for indexing
    this.db.setSetting(`project_index_${project.id}`, JSON.stringify({
      id: project.id,
      name: project.name,
      owner: project.owner,
      createdAt: project.createdAt,
      updatedAt: project.updatedAt
    }));

    return project;
  }

  /**
   * Load a project
   */
  loadProject(projectId) {
    const projectPath = path.join(this.projectsDir, `${projectId}.json`);

    if (!fs.existsSync(projectPath)) {
      throw new Error(`Project ${projectId} not found`);
    }

    const project = JSON.parse(fs.readFileSync(projectPath, 'utf-8'));
    this.currentProject = project;

    return project;
  }

  /**
   * Update a project
   */
  updateProject(projectId, updates) {
    const project = this.loadProject(projectId);

    // Merge updates
    Object.assign(project, updates);
    project.updatedAt = Date.now();

    // Save project file
    const projectPath = path.join(this.projectsDir, `${projectId}.json`);
    fs.writeFileSync(projectPath, JSON.stringify(project, null, 2));

    // Update index
    this.db.setSetting(`project_index_${project.id}`, JSON.stringify({
      id: project.id,
      name: project.name,
      owner: project.owner,
      createdAt: project.createdAt,
      updatedAt: project.updatedAt
    }));

    return project;
  }

  /**
   * Delete a project
   */
  deleteProject(projectId) {
    const projectPath = path.join(this.projectsDir, `${projectId}.json`);

    if (fs.existsSync(projectPath)) {
      fs.unlinkSync(projectPath);
    }

    // Remove from index
    this.db.setSetting(`project_index_${projectId}`, null);

    if (this.currentProject?.id === projectId) {
      this.currentProject = null;
    }
  }

  /**
   * List all projects
   */
  listProjects(filters = {}) {
    const projects = [];
    const files = fs.readdirSync(this.projectsDir);

    for (const file of files) {
      if (file.endsWith('.json')) {
        try {
          const project = JSON.parse(
            fs.readFileSync(path.join(this.projectsDir, file), 'utf-8')
          );

          // Apply filters
          if (filters.owner && project.owner !== filters.owner) continue;
          if (filters.tag && !project.metadata.tags.includes(filters.tag)) continue;

          projects.push({
            id: project.id,
            name: project.name,
            description: project.description,
            owner: project.owner,
            createdAt: project.createdAt,
            updatedAt: project.updatedAt,
            metadata: project.metadata
          });
        } catch (error) {
          console.error(`Error loading project ${file}:`, error);
        }
      }
    }

    return projects.sort((a, b) => b.updatedAt - a.updatedAt);
  }

  /**
   * Export project to file
   */
  exportProject(projectId, exportPath) {
    const project = this.loadProject(projectId);

    fs.writeFileSync(exportPath, JSON.stringify(project, null, 2));

    return exportPath;
  }

  /**
   * Import project from file
   */
  importProject(importPath) {
    const project = JSON.parse(fs.readFileSync(importPath, 'utf-8'));

    // Generate new ID to avoid conflicts
    project.id = this.generateProjectId();
    project.createdAt = Date.now();
    project.updatedAt = Date.now();

    return this.createProject(project);
  }

  /**
   * Apply project configuration to current session
   */
  applyProjectConfig(projectId, proxyBackend) {
    const project = this.loadProject(projectId);

    // Apply scope rules
    if (project.config.scope) {
      project.config.scope.forEach(rule => {
        proxyBackend.db.addScopeRule(rule);
      });
    }

    // Apply session rules
    if (project.config.sessionRules) {
      project.config.sessionRules.forEach(rule => {
        proxyBackend.sessionHandler.addRule(rule);
      });
    }

    // Apply macros
    if (project.config.macros) {
      project.config.macros.forEach(macro => {
        proxyBackend.sessionHandler.createMacro(macro);
      });
    }

    // Apply proxy settings
    if (project.config.proxySettings) {
      proxyBackend.db.setSetting('proxy-settings', project.config.proxySettings);
    }

    console.log(`Applied configuration from project: ${project.name}`);

    return project;
  }

  /**
   * Create scan configuration from project
   */
  createScanConfig(projectId) {
    const project = this.loadProject(projectId);

    return {
      projectId: project.id,
      projectName: project.name,
      scope: project.config.scope,
      scannerConfig: project.config.scannerConfig,
      spiderConfig: project.config.spiderConfig,
      policies: project.config.scanPolicies
    };
  }

  /**
   * Save scan results to project
   */
  saveScanResults(projectId, results) {
    const project = this.loadProject(projectId);

    if (!project.scanHistory) {
      project.scanHistory = [];
    }

    project.scanHistory.push({
      timestamp: Date.now(),
      vulnerabilityCount: results.vulnerabilities?.length || 0,
      endpointCount: results.endpoints?.length || 0,
      summary: results.summary || {}
    });

    // Keep only last 50 scan results
    if (project.scanHistory.length > 50) {
      project.scanHistory = project.scanHistory.slice(-50);
    }

    this.updateProject(projectId, project);
  }

  /**
   * Get current project
   */
  getCurrentProject() {
    return this.currentProject;
  }

  /**
   * Generate project ID
   */
  generateProjectId() {
    return `proj_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Duplicate project
   */
  duplicateProject(projectId, newName) {
    const project = this.loadProject(projectId);

    const newProject = {
      ...project,
      id: this.generateProjectId(),
      name: newName || `${project.name} (Copy)`,
      createdAt: Date.now(),
      updatedAt: Date.now(),
      scanHistory: [] // Don't copy scan history
    };

    return this.createProject(newProject);
  }
}

module.exports = ProjectManager;
