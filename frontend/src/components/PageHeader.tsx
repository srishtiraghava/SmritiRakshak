import React from 'react';

interface PageHeaderProps {
  title: string;
  description: string;
  actions?: React.ReactNode;
  titleId?: string;
}

export const PageHeader: React.FC<PageHeaderProps> = ({ title, description, actions, titleId }) => (
  <div className="page-heading">
    <div className="page-heading-copy">
      <h1 id={titleId}>{title}</h1>
      <p>{description}</p>
    </div>
    {actions && <div className="page-actions">{actions}</div>}
  </div>
);
