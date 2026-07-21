import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { SeverityBadge, SeverityGauge } from "./Severity";

describe("SeverityBadge", () => {
  it("renders the correct label for each severity level", () => {
    render(<SeverityBadge severity="critical" />);
    expect(screen.getByText("Critical")).toBeInTheDocument();
  });
});

describe("SeverityGauge", () => {
  it("renders an accessible label describing all severity counts", () => {
    render(<SeverityGauge counts={{ critical: 1, high: 2, medium: 0, low: 0, info: 0 }} />);
    const gauge = screen.getByRole("img");
    expect(gauge).toHaveAccessibleName("1 critical, 2 high, 0 medium, 0 low, 0 info");
  });

  it("renders a distinct empty state when there are zero findings", () => {
    const { container } = render(<SeverityGauge counts={{ critical: 0, high: 0, medium: 0, low: 0, info: 0 }} />);
    // Zero findings should not claim an "img" role with a misleading breakdown --
    // it's a plain neutral bar instead.
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
    expect(container.querySelector('[aria-label="No findings"]')).toBeInTheDocument();
  });

  it("proportions segment widths correctly relative to total findings", () => {
    render(<SeverityGauge counts={{ critical: 3, high: 1, medium: 0, low: 0, info: 0 }} />);
    const segments = screen.getAllByTitle(/Critical|High/);
    const criticalSegment = segments.find((s) => s.title === "3 Critical")!;
    expect(criticalSegment.style.width).toBe("75%");
  });
});
