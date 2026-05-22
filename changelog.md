# Changelog

All notable changes to SharpPress will be documented in this file.

## [1.0.0] - 2026-05-22

### Added

####  Admin Dashboard Redesign
- Complete redesign of admin interface with modern dark theme
- Responsive grid-based layout system
- Smooth animations and transitions
- Real-time statistics and metrics display
- Improved navigation with sidebar menu

####  Advanced User Management System
- User details modal with comprehensive information display
- Ban/Unban functionality for user accounts
- Account lock/unlock with configurable duration (default 60 minutes)
- Password reset token generation (24-hour expiry)
- Two-factor authentication (2FA) disable/manage
- User deletion with confirmation dialogs
- Live activity tracking with "last active" indicators
- Account status indicators (Online, Offline, Locked)
- Verification badges for verified email
- 2FA security badges
- Audit logging for all admin actions
- Toast notifications for all user actions
- Failed login attempt tracking and display

####  Enhanced Plugin System
- **New: Razor Pages Support** - Plugins can now register and manage Razor Pages with PageModels
- Plugin enable/disable functionality with proper state management
- Global plugin route protection via `PluginEnabledFilter`
- Automatic route blocking for disabled plugins (returns 404)
- Plugin type mapping system for route protection
- Admin menu item auto-hiding when plugin is disabled
- Menu item tracking and management per plugin
- Plugin statistics (total, active, disabled count)
- Plugin filter provider for cross-cutting authorization
- Better plugin lifecycle management
- Plugin state persistence and recovery

####  Enhanced Security
- Improved `UserControlMiddleware` with better error handling
- JWT token validation on every request
- Automatic token renewal when expiring soon (5-minute window)
- Banned user detection and suspension page display
- Maintenance mode with admin-only access bypass
- Cookie-based session management with secure flags
- HTTPS/Secure cookie requirements
- HttpOnly flag for token cookies
- Lax cookie policy

####  User Control Middleware (Internationalization)
- English language support (previously Persian/Farsi only)
- Professional ban notification page with:
  - Clear suspension message
  - Reason for suspension display
  - Support contact information
  - Appeal process link
  - Return to home button
- Maintenance mode page with:
  - Professional design
  - Estimated time display
  - Support contact option
  - Progress indicator animation
  - Helpful message
- Configurable support email and appeal URL
- Responsive design for all devices
- Smooth animations and modern styling

####  Role-Based Access Control
- Admin role with full system access
- Support role for customer support team
- Moderator role for content moderation
- User role for regular users
- Banned role with complete access restriction
- Role hierarchy and permission checking
- Multiple role assignment support
- Role-based filtering in user management

####  Plugin Architecture Improvements
- Type-to-plugin mapping for automatic route protection
- Plugin unloading with proper cleanup and GC
- Collectable assembly contexts for memory efficiency
- Plugin dependency resolution
- Unmanaged DLL support for native libraries

### Changed

#### Breaking Changes
- **Middleware registration order** - `PluginEnabledFilter` must be added to controller options
- **Plugin context** - Now includes `PluginManager` parameter
- **Menu service** - Added internal methods for tracking plugin menu items

#### Improvements
- User activity tracking now fire-and-forget to avoid blocking requests
- Better error messages in user control middleware
- Improved logging throughout user management system
- Password reset tokens now use GUID format
- Token expiry times more explicitly defined
- Plugin loading errors more descriptive
- Action descriptor cache invalidation more thorough

### Fixed

- Plugin routes not being blocked when disabled
- Menu items remaining visible for disabled plugins
- Token renewal not persisting renewed token
- User activity not updating correctly
- Failed login attempts not being tracked
- Password reset tokens not being generated properly
- Type discovery issues in plugin assemblies
- Modal not closing after user deletion
- Action buttons not disabling during request

### Security

- Added CSRF protection to user management actions
- Improved JWT token validation
- Better password reset token security
- Admin-only endpoint protection on all user actions
- Confirmation dialogs for destructive actions
- Audit logging for all user modifications
- Rate limiting ready (framework in place)

### Performance

- Optimized user query with pagination (default 100 users)
- Lazy-loaded user details in modal
- Efficient plugin type mapping
- Minimal database queries for activity updates
- Compiled Razor Pages for faster rendering
- Optimized CSS with modern grid system

### Dependencies

- ASP.NET Core 6.0+ requirement maintained
- No new external dependencies added
- Uses built-in ASP.NET Core features