import { Suspense, lazy } from "react";
import { BrowserRouter, Route, Routes, Navigate } from "react-router-dom";
import { Layout, LoadingState } from "./components/Layout";
import { ReviewsListPage } from "./pages/ReviewsListPage";
import { AuthProvider, useAuth } from "./components/AuthProvider";
import { LandingPage } from "./pages/LandingPage";
import { RepositoriesPage } from "./pages/RepositoriesPage";
import { SettingsPage } from "./pages/SettingsPage";

import { DashboardPage } from "./pages/DashboardPage";
import { AnalyticsPage } from "./pages/AnalyticsPage";

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { user } = useAuth();
  if (!user) {
    return <Navigate to="/" replace />;
  }
  return <>{children}</>;
}

function RootRoute() {
  const { user } = useAuth();
  if (!user) {
    return <LandingPage />;
  }
  return <DashboardPage />;
}

// Code-split: EvaluationPage pulls in recharts (a genuinely heavy
// dependency), which was inflating the main bundle to 611kB even for
// someone who only ever looks at the reviews list. Lazy-loading it means
// that cost is only paid by someone who actually navigates there.
const ReviewDetailPage = lazy(() =>
  import("./pages/ReviewDetailPage").then((m) => ({ default: m.ReviewDetailPage })),
);
const EvaluationPage = lazy(() => import("./pages/EvaluationPage").then((m) => ({ default: m.EvaluationPage })));
const ObservabilityPage = lazy(() =>
  import("./pages/ObservabilityPage").then((m) => ({ default: m.ObservabilityPage })),
);

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Layout>
          <Suspense fallback={<LoadingState label="Loading page" />}>
            <Routes>
              <Route path="/" element={<RootRoute />} />
              <Route
                path="/analytics"
                element={
                  <ProtectedRoute>
                    <AnalyticsPage />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/reviews"
                element={
                  <ProtectedRoute>
                    <ReviewsListPage />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/repositories"
                element={
                  <ProtectedRoute>
                    <RepositoriesPage />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/reviews/:reviewId"
                element={
                  <ProtectedRoute>
                    <ReviewDetailPage />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/evaluation"
                element={
                  <ProtectedRoute>
                    <EvaluationPage />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/observability"
                element={
                  <ProtectedRoute>
                    <ObservabilityPage />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/settings"
                element={
                  <ProtectedRoute>
                    <SettingsPage />
                  </ProtectedRoute>
                }
              />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </Suspense>
        </Layout>
      </BrowserRouter>
    </AuthProvider>
  );
}
