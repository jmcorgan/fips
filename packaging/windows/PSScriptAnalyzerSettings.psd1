# PSScriptAnalyzer settings for FIPS Windows packaging scripts.
#
# Starts from the default ruleset and excludes a small set of rules that
# do not apply to operator-facing installer scripts. Each exclusion lists
# why it was suppressed and which scripts justify it.

@{
    # Skip Information-level findings; gate CI on Warning and Error only.
    Severity = @('Error', 'Warning')

    ExcludeRules = @(
        # Console output to the operator is intentional in build-zip.ps1,
        # install-service.ps1, and uninstall-service.ps1. These scripts
        # are run interactively by humans installing/packaging FIPS, and
        # Write-Host gives them feedback at the terminal. Switching to
        # Write-Output would conflate progress text with the (non-existent)
        # script return value.
        'PSAvoidUsingWriteHost',

        # Copy-Item, New-Item, and similar cmdlet calls in the installer
        # use positional parameters (source, destination) for readability
        # and to mirror cp/mv conventions Unix-familiar operators expect.
        'PSAvoidUsingPositionalParameters'
    )
}
