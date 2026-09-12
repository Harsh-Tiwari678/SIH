"use client"

import * as React from "react"
import { cn } from "@/lib/utils"
import {
  type OrgMemberRole,
  ORG_ROLES,
  ORG_ROLE_LABELS,
} from "@/lib/organization-api/organization-member-client"

const ROLE_DESCRIPTIONS: Record<OrgMemberRole, string> = {
  admin: "Can add, remove, and change member roles",
  investigator: "",
  member: "",
}

export function OrgRolePicker({
  value,
  onChange,
  disabled,
}: {
  value: OrgMemberRole
  onChange: (role: OrgMemberRole) => void
  disabled?: boolean
}) {
  return (
    <fieldset>
      <legend className="text-sm font-medium text-foreground">Role</legend>
      <div
        className="mt-2 space-y-1.5"
        role="radiogroup"
        aria-label="Organization role"
      >
        {ORG_ROLES.map((r) => {
          const checked = r === value
          return (
            <label
              key={r}
              className={cn(
                "rounded-md border px-3 py-2 text-sm transition-colors duration-150",
                checked
                  ? "border-primary/50 bg-primary/5"
                  : "border-border/70 hover:bg-muted/50",
                !disabled && "cursor-pointer",
              )}
            >
              <span className="flex items-center gap-2">
                <input
                  type="radio"
                  name="org-role"
                  value={r}
                  checked={checked}
                  onChange={() => onChange(r)}
                  disabled={disabled}
                  className="mt-px"
                />
                <span
                  className={cn(
                    "font-medium",
                    checked ? "text-foreground" : "text-muted-foreground",
                  )}
                >
                  {ORG_ROLE_LABELS[r]}
                </span>
              </span>
              {ROLE_DESCRIPTIONS[r] ? (
                <p className="ml-6 mt-0.5 text-xs text-muted-foreground">
                  {ROLE_DESCRIPTIONS[r]}
                </p>
              ) : null}
            </label>
          )
        })}
      </div>
    </fieldset>
  )
}