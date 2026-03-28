import { Injectable, Logger } from '@nestjs/common';
import {
  ComplianceAlert,
  AlertType,
  RiskLevel,
  AlertStatus,
  RecommendationType,
  Priority
} from '../interfaces/regulatory-arbitrage.interface';

@Injectable()
export class ComplianceTeamIntegrationService {
  private readonly logger = new Logger(ComplianceTeamIntegrationService.name);
  private readonly teamMembers = new Map<string, any>();
  private readonly workloads = new Map<string, any>();
  private readonly escalations = new Map<string, any>();
  private readonly performanceMetrics = new Map<string, any>();

  constructor() {
    this.initializeTeamMembers();
  }

  async assignAlert(
    alertId: string,
    teamMemberId: string,
    priority: Priority = Priority.MEDIUM,
    notes?: string
  ): Promise<{
    success: boolean;
    assignedTo?: string;
    estimatedResolutionTime?: Date;
    error?: string;
  }> {
    const startTime = Date.now();
    
    this.logger.log(`Assigning alert ${alertId} to team member ${teamMemberId}`);

    try {
      const teamMember = this.teamMembers.get(teamMemberId);
      if (!teamMember) {
        return {
          success: false,
          error: `Team member not found: ${teamMemberId}`
        };
      }

      // Check availability
      if (!teamMember.available) {
        return {
          success: false,
          error: `Team member not available: ${teamMemberId}`
        };
      }

      // Check specialization match
      const alert = await this.getAlertDetails(alertId);
      if (!this.canHandleAlert(teamMember, alert)) {
        return {
          success: false,
          error: `Team member lacks specialization: ${teamMemberId}`
        };
      }

      // Check workload
      const currentWorkload = this.workloads.get(teamMemberId) || { active: 0, capacity: 10 };
      if (currentWorkload.active >= currentWorkload.capacity) {
        return {
          success: false,
          error: `Team member at capacity: ${teamMemberId}`
        };
      }

      // Assign alert
      const assignment = {
        alertId,
        assignedAt: new Date(),
        assignedBy: 'system',
        priority,
        estimatedResolutionTime: this.calculateEstimatedResolutionTime(alert, teamMember),
        notes: notes || ''
      };

      // Update workload
      currentWorkload.active++;
      this.workloads.set(teamMemberId, currentWorkload);

      // Record assignment
      if (!teamMember.assignments) {
        teamMember.assignments = [];
      }
      teamMember.assignments.push(assignment);

      // Send notification
      await this.notifyTeamMember(teamMemberId, 'alert_assigned', {
        alertId,
        priority,
        estimatedResolutionTime: assignment.estimatedResolutionTime
      });

      const endTime = Date.now();
      
      this.logger.log(`Alert ${alertId} assigned to ${teamMemberId} in ${endTime - startTime}ms`);
      
      return {
        success: true,
        assignedTo: teamMember.email,
        estimatedResolutionTime: assignment.estimatedResolutionTime
      };
      
    } catch (error) {
      this.logger.error(`Failed to assign alert ${alertId}:`, error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  async reassignAlert(
    alertId: string,
    fromTeamMemberId: string,
    toTeamMemberId: string,
    reason: string
  ): Promise<{
    success: boolean;
    error?: string;
  }> {
    const startTime = Date.now();
    
    this.logger.log(`Reassigning alert ${alertId} from ${fromTeamMemberId} to ${toTeamMemberId}`);

    try {
      const fromMember = this.teamMembers.get(fromTeamMemberId);
      const toMember = this.teamMembers.get(toTeamMemberId);
      
      if (!fromMember || !toMember) {
        return {
          success: false,
          error: 'Team member not found'
        };
      }

      // Remove from current member
      fromMember.assignments = fromMember.assignments.filter(
        assignment => assignment.alertId !== alertId
      );
      
      // Update workload
      const fromWorkload = this.workloads.get(fromTeamMemberId) || { active: 0, capacity: 10 };
      fromWorkload.active--;
      this.workloads.set(fromTeamMemberId, fromWorkload);

      // Assign to new member
      const reassignment = {
        alertId,
        reassignedAt: new Date(),
        reassignedBy: 'system',
        fromTeamMemberId,
        reason,
        notes: `Reassigned from ${fromMember.name} to ${toMember.name}: ${reason}`
      };

      if (!toMember.assignments) {
        toMember.assignments = [];
      }
      toMember.assignments.push(reassignment);

      // Update workload
      const toWorkload = this.workloads.get(toTeamMemberId) || { active: 0, capacity: 10 };
      toWorkload.active++;
      this.workloads.set(toTeamMemberId, toWorkload);

      // Send notifications
      await this.notifyTeamMember(fromTeamMemberId, 'alert_reassigned', {
        alertId,
        reason,
        toTeamMember: toMember.name
      });

      await this.notifyTeamMember(toTeamMemberId, 'alert_assigned', {
        alertId,
        reassigned: true,
        fromTeamMember: fromMember.name,
        reason
      });

      const endTime = Date.now();
      
      this.logger.log(`Alert ${alertId} reassigned in ${endTime - startTime}ms`);
      
      return { success: true };
      
    } catch (error) {
      this.logger.error(`Failed to reassign alert ${alertId}:`, error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  async escalateAlert(
    alertId: string,
    escalationLevel: number,
    reason: string,
    escalatedBy?: string
  ): Promise<{
    success: boolean;
    escalatedTo?: string;
    error?: string;
  }> {
    const startTime = Date.now();
    
    this.logger.log(`Escalating alert ${alertId} to level ${escalationLevel}`);

    try {
      const alert = await this.getAlertDetails(alertId);
      const escalationTarget = this.getEscalationTarget(alert, escalationLevel);
      
      if (!escalationTarget) {
        return {
          success: false,
          error: 'No escalation target available'
        };
      }

      // Create escalation record
      const escalation = {
        alertId,
        escalationLevel,
        reason,
        escalatedBy: escalatedBy || 'system',
        escalatedAt: new Date(),
        escalatedTo: escalationTarget.id,
        previousAssignee: alert.assignedTo,
        acknowledged: false,
        resolved: false
      };

      this.escalations.set(alertId, escalation);

      // Update alert status
      await this.updateAlertStatus(alertId, AlertStatus.ESCALATED, escalationTarget.email);

      // Send notifications
      await this.notifyEscalation(alert, escalation, escalationTarget);

      const endTime = Date.now();
      
      this.logger.log(`Alert ${alertId} escalated to ${escalationTarget.name} in ${endTime - startTime}ms`);
      
      return {
        success: true,
        escalatedTo: escalationTarget.email
      };
      
    } catch (error) {
      this.logger.error(`Failed to escalate alert ${alertId}:`, error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  async acknowledgeAlert(
    alertId: string,
    teamMemberId: string,
    notes?: string
  ): Promise<{
    success: boolean;
    error?: string;
  }> {
    const startTime = Date.now();
    
    this.logger.log(`Acknowledging alert ${alertId} by ${teamMemberId}`);

    try {
      const teamMember = this.teamMembers.get(teamMemberId);
      if (!teamMember) {
        return {
          success: false,
          error: `Team member not found: ${teamMemberId}`
        };
      }

      // Find the assignment
      const assignment = teamMember.assignments?.find(
        assignment => assignment.alertId === alertId
      );

      if (!assignment) {
        return {
          success: false,
          error: `Alert not assigned to team member: ${alertId}`
        };
      }

      // Update assignment
      assignment.acknowledgedAt = new Date();
      assignment.acknowledgedBy = teamMemberId;
      assignment.notes = notes || '';

      // Send notification
      await this.notifyTeamMember(teamMemberId, 'alert_acknowledged', {
        alertId,
        acknowledgedAt: assignment.acknowledgedAt
      });

      const endTime = Date.now();
      
      this.logger.log(`Alert ${alertId} acknowledged in ${endTime - startTime}ms`);
      
      return { success: true };
      
    } catch (error) {
      this.logger.error(`Failed to acknowledge alert ${alertId}:`, error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  async resolveAlert(
    alertId: string,
    teamMemberId: string,
    resolution: string,
    notes?: string
  ): Promise<{
    success: boolean;
    resolutionTime?: number;
    error?: string;
  }> {
    const startTime = Date.now();
    
    this.logger.log(`Resolving alert ${alertId} by ${teamMemberId}`);

    try {
      const teamMember = this.teamMembers.get(teamMemberId);
      if (!teamMember) {
        return {
          success: false,
          error: `Team member not found: ${teamMemberId}`
        };
      }

      // Find the assignment
      const assignment = teamMember.assignments?.find(
        assignment => assignment.alertId === alertId
      );

      if (!assignment) {
        return {
          success: false,
          error: `Alert not assigned to team member: ${alertId}`
        };
      }

      // Update assignment
      assignment.resolvedAt = new Date();
      assignment.resolvedBy = teamMemberId;
      assignment.resolution = resolution;
      assignment.notes = notes || '';

      // Calculate resolution time
      const resolutionTime = assignment.resolvedAt.getTime() - assignment.assignedAt.getTime();

      // Update workload
      const workload = this.workloads.get(teamMemberId) || { active: 0, capacity: 10 };
      workload.active--;
      this.workloads.set(teamMemberId, workload);

      // Update performance metrics
      this.updatePerformanceMetrics(teamMemberId, {
        resolved: true,
        resolutionTime,
        resolutionType: this.categorizeResolution(resolution)
      });

      // Update alert status
      await this.updateAlertStatus(alertId, AlertStatus.RESOLVED, teamMember.email);

      // Send notification
      await this.notifyTeamMember(teamMemberId, 'alert_resolved', {
        alertId,
        resolution,
        resolutionTime
      });

      const endTime = Date.now();
      
      this.logger.log(`Alert ${alertId} resolved in ${endTime - startTime}ms`);
      
      return {
        success: true,
        resolutionTime
      };
      
    } catch (error) {
      this.logger.error(`Failed to resolve alert ${alertId}:`, error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  async getTeamWorkload(): Promise<{
    teamMembers: any[];
    totalActive: number;
    totalCapacity: number;
    utilizationRate: number;
    overloadMembers: string[];
  }> {
    const teamMembers = Array.from(this.teamMembers.values());
    let totalActive = 0;
    let totalCapacity = 0;
    const overloadMembers: string[] = [];

    teamMembers.forEach(member => {
      const workload = this.workloads.get(member.id) || { active: 0, capacity: 10 };
      
      totalActive += workload.active;
      totalCapacity += workload.capacity;
      
      member.workload = workload;
      member.utilizationRate = workload.active / workload.capacity;
      
      if (workload.active > workload.capacity) {
        overloadMembers.push(member.id);
      }
    });

    const utilizationRate = totalCapacity > 0 ? totalActive / totalCapacity : 0;

    return {
      teamMembers,
      totalActive,
      totalCapacity,
      utilizationRate,
      overloadMembers
    };
  }

  async getTeamPerformance(
    timeRange?: { start: Date; end: Date }
  ): Promise<{
    members: any[];
    teamMetrics: any;
    topPerformers: any[];
    improvementAreas: any[];
  }> {
    const teamMembers = Array.from(this.teamMembers.values());
    const members = [];
    
    // Calculate individual performance metrics
    teamMembers.forEach(member => {
      const metrics = this.performanceMetrics.get(member.id) || {
        totalAssigned: 0,
        totalResolved: 0,
        averageResolutionTime: 0,
        escalationRate: 0,
        satisfactionScore: 0
      };

      member.performance = metrics;
      members.push(member);
    });

    // Calculate team metrics
    const teamMetrics = {
      totalAssigned: members.reduce((sum, member) => sum + member.performance.totalAssigned, 0),
      totalResolved: members.reduce((sum, member) => sum + member.performance.totalResolved, 0),
      averageResolutionTime: members.reduce((sum, member) => sum + member.performance.averageResolutionTime, 0) / members.length,
      overallEscalationRate: members.reduce((sum, member) => sum + member.performance.escalationRate, 0) / members.length,
      teamUtilization: await this.calculateTeamUtilization()
    };

    // Identify top performers
    const topPerformers = members
      .filter(member => member.performance.totalResolved > 0)
      .sort((a, b) => {
        const scoreA = this.calculatePerformanceScore(a.performance);
        const scoreB = this.calculatePerformanceScore(b.performance);
        return scoreB - scoreA;
      })
      .slice(0, 5);

    // Identify improvement areas
    const improvementAreas = this.identifyImprovementAreas(members);

    return {
      members,
      teamMetrics,
      topPerformers,
      improvementAreas
    };
  }

  async optimizeWorkload(): Promise<{
    optimizations: any[];
    recommendations: string[];
  }> {
    const startTime = Date.now();
    
    this.logger.log('Optimizing team workload');

    try {
      const workload = await this.getTeamWorkload();
      const optimizations = [];
      const recommendations = [];

      // Identify underutilized members
      const underutilized = workload.teamMembers.filter(member => 
        member.utilizationRate < 0.5
      );

      // Identify overloaded members
      const overloaded = workload.overloadMembers;

      // Suggest reassignments
      if (overloaded.length > 0 && underutilized.length > 0) {
        const reassignments = this.suggestReassignments(overloaded, underutilized);
        optimizations.push(...reassignments);
        recommendations.push('Consider reassigning alerts from overloaded to underutilized team members');
      }

      // Suggest capacity adjustments
      if (workload.utilizationRate > 0.8) {
        recommendations.push('Consider increasing team capacity or adding team members');
      }

      // Suggest workload balancing
      if (workload.utilizationRate > 0.9) {
        recommendations.push('Implement automatic workload balancing for new alerts');
      }

      const endTime = Date.now();
      
      this.logger.log(`Workload optimization completed in ${endTime - startTime}ms`);
      
      return {
        optimizations,
        recommendations
      };
      
    } catch (error) {
      this.logger.error('Failed to optimize workload:', error);
      throw error;
    }
  }

  async getEscalationHistory(
    alertId?: string,
    timeRange?: { start: Date; end: Date }
  ): Promise<any[]> {
    let escalations = Array.from(this.escalations.values());

    // Apply filters
    if (alertId) {
      escalations = escalations.filter(esc => esc.alertId === alertId);
    }

    if (timeRange) {
      escalations = escalations.filter(esc => 
        esc.escalatedAt >= timeRange.start &&
        esc.escalatedAt <= timeRange.end
      );
    }

    return escalations.sort((a, b) => b.escalatedAt.getTime() - a.escalatedAt.getTime());
  }

  async scheduleFollowUp(
    alertId: string,
    teamMemberId: string,
    followUpTime: Date,
    notes?: string
  ): Promise<{
    success: boolean;
    followUpId?: string;
    error?: string;
  }> {
    const startTime = Date.now();
    
    this.logger.log(`Scheduling follow-up for alert ${alertId}`);

    try {
      const teamMember = this.teamMembers.get(teamMemberId);
      if (!teamMember) {
        return {
          success: false,
          error: `Team member not found: ${teamMemberId}`
        };
      }

      const followUp = {
        id: `followup_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        alertId,
        teamMemberId,
        scheduledTime: followUpTime,
        notes: notes || '',
        status: 'scheduled',
        createdAt: new Date()
      };

      if (!teamMember.followUps) {
        teamMember.followUps = [];
      }
      teamMember.followUps.push(followUp);

      // Send notification
      await this.notifyTeamMember(teamMemberId, 'follow_up_scheduled', {
        alertId,
        followUpTime,
        followUpId: followUp.id
      });

      const endTime = Date.now();
      
      this.logger.log(`Follow-up scheduled in ${endTime - startTime}ms`);
      
      return {
        success: true,
        followUpId: followUp.id
      };
      
    } catch (error) {
      this.logger.error(`Failed to schedule follow-up for alert ${alertId}:`, error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  private async getAlertDetails(alertId: string): Promise<ComplianceAlert> {
    // This would integrate with the alerting service
    // For now, return a mock alert
    return {
      id: alertId,
      userId: 'user_123',
      type: AlertType.SUSPICIOUS_PATTERN,
      severity: RiskLevel.MEDIUM,
      title: 'Mock Alert',
      description: 'Mock alert for testing',
      evidence: {} as any,
      jurisdiction: 'US',
      regulations: [],
      recommendations: [],
      detected: new Date(),
      status: AlertStatus.OPEN
    };
  }

  private canHandleAlert(teamMember: any, alert: ComplianceAlert): boolean {
    // Check if team member can handle the alert type
    return teamMember.specializations?.includes(alert.type) || 
           teamMember.role === 'senior_compliance_officer';
  }

  private calculateEstimatedResolutionTime(alert: ComplianceAlert, teamMember: any): Date {
    // Calculate estimated resolution time based on alert severity and member experience
    const baseTimes = {
      [RiskLevel.LOW]: 4 * 60 * 60 * 1000, // 4 hours
      [RiskLevel.MEDIUM]: 24 * 60 * 60 * 1000, // 24 hours
      [RiskLevel.HIGH]: 72 * 60 * 60 * 1000, // 3 days
      [RiskLevel.CRITICAL]: 24 * 60 * 60 * 1000 // 24 hours (high priority)
    };

    const experienceMultiplier = teamMember.experienceLevel === 'senior' ? 0.8 : 
                               teamMember.experienceLevel === 'mid' ? 1.0 : 1.2;

    const baseTime = baseTimes[alert.severity] || baseTimes[RiskLevel.MEDIUM];
    const adjustedTime = baseTime * experienceMultiplier;

    return new Date(Date.now() + adjustedTime);
  }

  private getEscalationTarget(alert: ComplianceAlert, level: number): any {
    // Get escalation target based on alert type and level
    const escalationMatrix = {
      [AlertType.REGULATORY_ARBITRAGE]: {
        1: this.getTeamMemberByRole('regulatory_specialist'),
        2: this.getTeamMemberByRole('senior_regulatory_specialist'),
        3: this.getTeamMemberByRole('head_of_compliance')
      },
      [AlertType.TAX_EVASION]: {
        1: this.getTeamMemberByRole('tax_specialist'),
        2: this.getTeamMemberByRole('senior_tax_specialist'),
        3: this.getTeamMemberByRole('head_of_tax_compliance')
      },
      [AlertType.JURISDICTION_JUMPING]: {
        1: this.getTeamMemberByRole('jurisdiction_specialist'),
        2: this.getTeamMemberByRole('senior_jurisdiction_specialist'),
        3: this.getTeamMemberByRole('head_of_compliance')
      }
    };

    return escalationMatrix[alert.type]?.[level] || this.getTeamMemberByRole('senior_compliance_officer');
  }

  private getTeamMemberByRole(role: string): any {
    return Array.from(this.teamMembers.values())
      .find(member => member.role === role && member.available) ||
             this.getAvailableTeamMember();
  }

  private getAvailableTeamMember(): any {
    return Array.from(this.teamMembers.values())
      .find(member => member.available) || {
        id: 'default',
        name: 'Default Team Member',
        email: 'default@company.com',
        role: 'compliance_officer',
        available: true
      };
  }

  private async notifyTeamMember(teamMemberId: string, eventType: string, data: any): Promise<void> {
    // Send notification to team member
    const teamMember = this.teamMembers.get(teamMemberId);
    if (teamMember) {
      this.logger.log(`Notification sent to ${teamMember.name}: ${eventType}`, data);
    }
  }

  private async notifyEscalation(alert: ComplianceAlert, escalation: any, target: any): Promise<void> {
    // Send escalation notifications
    this.logger.log(`Escalation notification sent for alert ${alert.id} to ${target.name}`);
  }

  private async updateAlertStatus(alertId: string, status: AlertStatus, assignedTo?: string): Promise<void> {
    // Update alert status (would integrate with alerting service)
    this.logger.log(`Alert ${alertId} status updated to ${status}`);
  }

  private categorizeResolution(resolution: string): string {
    // Categorize resolution type
    const categories = {
      'compliant': ['user_cooperated', 'issue_resolved', 'no_violation'],
      'violation': ['user_suspended', 'penalty_applied', 'regulatory_action'],
      'false_positive': ['error', 'misunderstanding', 'system_issue'],
      'other': []
    };

    for (const [category, keywords] of Object.entries(categories)) {
      if (keywords.some(keyword => resolution.toLowerCase().includes(keyword))) {
        return category;
      }
    }

    return 'other';
  }

  private updatePerformanceMetrics(teamMemberId: string, metrics: any): void {
    const current = this.performanceMetrics.get(teamMemberId) || {
      totalAssigned: 0,
      totalResolved: 0,
      averageResolutionTime: 0,
      escalationRate: 0,
      satisfactionScore: 0
    };

    if (metrics.resolved) {
      current.totalResolved++;
      current.averageResolutionTime = (
        (current.averageResolutionTime * (current.totalResolved - 1) + metrics.resolutionTime) / 
        current.totalResolved
      );
    }

    if (metrics.escalated) {
      current.escalationRate = (
        (current.escalationRate * (current.totalAssigned) + 1) / 
        (current.totalAssigned + 1)
      );
    }

    current.totalAssigned++;

    this.performanceMetrics.set(teamMemberId, current);
  }

  private calculatePerformanceScore(metrics: any): number {
    // Calculate overall performance score
    const resolutionRate = metrics.totalAssigned > 0 ? metrics.totalResolved / metrics.totalAssigned : 0;
    const timeScore = metrics.averageResolutionTime > 0 ? Math.min(100, 1000000 / metrics.averageResolutionTime) : 0;
    const escalationPenalty = metrics.escalationRate * 20;

    return resolutionRate * 40 + timeScore * 30 + (100 - escalationPenalty);
  }

  private async calculateTeamUtilization(): Promise<number> {
    const workload = await this.getTeamWorkload();
    return workload.utilizationRate;
  }

  private identifyImprovementAreas(members: any[]): any[] {
    // Identify areas for improvement
    const areas = [];

    // Low resolution rate
    const lowResolutionMembers = members.filter(member => 
      member.performance.totalAssigned > 10 && 
      (member.performance.totalResolved / member.performance.totalAssigned) < 0.7
    );

    if (lowResolutionMembers.length > 0) {
      areas.push({
        type: 'low_resolution_rate',
        members: lowResolutionMembers.map(m => m.id),
        recommendation: 'Provide additional training and mentorship',
        impact: 'high'
      });
    }

    // High escalation rate
    const highEscalationMembers = members.filter(member => 
      member.performance.escalationRate > 0.3
    );

    if (highEscalationMembers.length > 0) {
      areas.push({
        type: 'high_escalation_rate',
        members: highEscalationMembers.map(m => m.id),
        recommendation: 'Review case complexity and provide additional resources',
        impact: 'medium'
      });
    }

    // Slow resolution time
    const slowResolutionMembers = members.filter(member => 
      member.performance.averageResolutionTime > 72 * 60 * 60 * 1000 // 3 days
    );

    if (slowResolutionMembers.length > 0) {
      areas.push({
        type: 'slow_resolution_time',
        members: slowResolutionMembers.map(m => m.id),
        recommendation: 'Provide process optimization and tools',
        impact: 'medium'
      });
    }

    return areas;
  }

  private suggestReassignments(overloaded: string[], underutilized: string[]): any[] {
    const suggestions = [];

    overloaded.forEach(overloadedId => {
      const overloadedMember = this.teamMembers.get(overloadedId);
      if (!overloadedMember) return;

      // Find suitable underutilized member
      const suitableUnderutilized = underutilized.find(underutilizedId => {
        const underutilizedMember = this.teamMembers.get(underutilizedId);
        return underutilizedMember && 
               this.canHandleAlert(underutilizedMember, overloadedMember.assignments[0]?.alert);
      });

      if (suitableUnderutilized) {
        // Find reassignable alerts (low priority)
        const reassignableAlerts = overloadedMember.assignments?.filter(
          assignment => assignment.priority === Priority.LOW
        ) || [];

        reassignableAlerts.slice(0, 2).forEach(assignment => {
          suggestions.push({
            from: overloadedId,
            to: suitableUnderutilized,
            alertId: assignment.alertId,
            reason: 'Workload balancing'
          });
        });
      }
    });

    return suggestions;
  }

  private initializeTeamMembers(): void {
    // Initialize team members
    const members = [
      {
        id: 'member_1',
        name: 'Sarah Johnson',
        email: 'sarah.johnson@company.com',
        role: 'senior_compliance_officer',
        specializations: [AlertType.REGULATORY_ARBITRAGE, AlertType.TAX_EVASION],
        experienceLevel: 'senior',
        available: true,
        onCall: true,
        assignments: [],
        followUps: [],
        performance: {
          totalAssigned: 0,
          totalResolved: 0,
          averageResolutionTime: 0,
          escalationRate: 0,
          satisfactionScore: 0
        }
      },
      {
        id: 'member_2',
        name: 'Mike Chen',
        email: 'mike.chen@company.com',
        role: 'compliance_analyst',
        specializations: [AlertType.SUSPICIOUS_PATTERN, AlertType.AUTOMATED_BEHAVIOR],
        experienceLevel: 'mid',
        available: true,
        onCall: false,
        assignments: [],
        followUps: [],
        performance: {
          totalAssigned: 0,
          totalResolved: 0,
          averageResolutionTime: 0,
          escalationRate: 0,
          satisfactionScore: 0
        }
      },
      {
        id: 'member_3',
        name: 'Emily Davis',
        email: 'emily.davis@company.com',
        role: 'regulatory_specialist',
        specializations: [AlertType.JURISDICTION_JUMPING, AlertType.CROSS_BORDER_ANOMALY],
        experienceLevel: 'senior',
        available: true,
        onCall: false,
        assignments: [],
        followUps: [],
        performance: {
          totalAssigned: 0,
          totalResolved: 0,
          averageResolutionTime: 0,
          escalationRate: 0,
          satisfactionScore: 0
        }
      },
      {
        id: 'member_4',
        name: 'James Wilson',
        email: 'james.wilson@company.com',
        role: 'tax_specialist',
        specializations: [AlertType.TAX_EVASION, AlertType.STRUCTURED_TRANSACTIONS],
        experienceLevel: 'mid',
        available: true,
        onCall: false,
        assignments: [],
        followUps: [],
        performance: {
          totalAssigned: 0,
          totalResolved: 0,
          averageResolutionTime: 0,
          escalationRate: 0,
          satisfactionScore: 0
        }
      }
    ];

    members.forEach(member => {
      this.teamMembers.set(member.id, member);
    });

    this.logger.log(`Initialized compliance team with ${members.length} members`);
  }

  async getTeamMemberDetails(teamMemberId: string): Promise<any> {
    return this.teamMembers.get(teamMemberId) || null;
  }

  async updateTeamMemberAvailability(
    teamMemberId: string,
    available: boolean
  ): Promise<void> {
    const member = this.teamMembers.get(teamMemberId);
    if (member) {
      member.available = available;
      this.logger.log(`Team member ${teamMemberId} availability updated to ${available}`);
    }
  }

  async getTeamSchedule(): Promise<{
    members: any[];
    onCallMembers: string[];
    coverage: any;
  }> {
    const members = Array.from(this.teamMembers.values());
    const onCallMembers = members
      .filter(member => member.onCall)
      .map(member => member.id);

    const coverage = {
      weekdays: this.calculateCoverage(members, 'weekday'),
      weekends: this.calculateCoverage(members, 'weekend'),
      holidays: this.calculateCoverage(members, 'holiday')
    };

    return {
      members,
      onCallMembers,
      coverage
    };
  }

  private calculateCoverage(members: any[], period: string): any {
    // Calculate team coverage for different periods
    const availableMembers = members.filter(member => member.available);
    
    return {
      total: members.length,
      available: availableMembers.length,
      percentage: members.length > 0 ? (availableMembers.length / members.length) * 100 : 0,
      period
    };
  }
}
