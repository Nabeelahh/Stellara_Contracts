import { Injectable, Logger } from '@nestjs/common';
import * as Handlebars from 'handlebars';

@Injectable()
export class TemplateService {
  private readonly logger = new Logger(TemplateService.name);
  private templates: Map<string, Handlebars.TemplateDelegate> = new Map();

  constructor() {
    this.registerDefaultTemplates();
  }

  private registerDefaultTemplates() {
    this.registerTemplate(
      'CONTRIBUTION',
      'New contribution of {{amount}} received for project {{projectTitle}}.',
    );
    this.registerTemplate(
      'MILESTONE',
      'Milestone {{milestoneTitle}} for project {{projectTitle}} has been {{status}}.',
    );
    this.registerTemplate(
      'DEADLINE',
      'Deadline for project {{projectTitle}} is approaching: {{deadline}}.',
    );
    this.registerTemplate('SYSTEM', 'System notification: {{message}}');
  }

  registerTemplate(name: string, content: string) {
    this.templates.set(name, Handlebars.compile(content));
  }

  render(templateName: string, context: any): string {
    const template = this.templates.get(templateName);
    if (!template) {
      return context.message || `Notification: ${templateName}`;
    }
    return template(context);
  }
}
