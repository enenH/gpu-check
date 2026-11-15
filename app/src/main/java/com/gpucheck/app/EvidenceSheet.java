package com.gpucheck.app;

import android.app.Activity;
import android.app.Application;
import android.app.Dialog;
import android.graphics.Color;
import android.graphics.Rect;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.StateListDrawable;
import android.os.Build;
import android.os.Bundle;
import android.text.Layout;
import android.util.DisplayMetrics;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.view.Window;
import android.view.WindowInsets;
import android.view.WindowManager;
import android.view.WindowMetrics;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/** A selectable, bounded evidence panel that never outlives its owning activity. */
final class EvidenceSheet {
    private static final int SURFACE = Color.rgb(16, 25, 36);
    private static final int BORDER = Color.rgb(38, 50, 66);
    private static final int TEXT = Color.rgb(243, 245, 247);
    private static final int MUTED = Color.rgb(155, 169, 187);
    private static final int ACCENT = Color.rgb(214, 245, 139);

    private EvidenceSheet() { }

    static void show(Activity activity, String title, String subtitle, CharSequence content,
            boolean monospace, String secondaryLabel, Runnable secondaryAction) {
        if (!canShow(activity)) return;

        Dialog dialog = new Dialog(activity, android.R.style.Theme_Material_Dialog_NoActionBar);
        dialog.setOwnerActivity(activity);
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);
        dialog.setCancelable(true);
        dialog.setCanceledOnTouchOutside(true);

        BoundedColumn sheet = new BoundedColumn(activity);
        sheet.setOrientation(LinearLayout.VERTICAL);
        sheet.setBackground(panelBackground(activity));
        if (Build.VERSION.SDK_INT >= 28) sheet.setAccessibilityPaneTitle(title);

        View handle = new View(activity);
        handle.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        handle.setBackground(shape(activity, BORDER, BORDER, 2));
        LinearLayout.LayoutParams handleParams = new LinearLayout.LayoutParams(dp(activity, 34), dp(activity, 4));
        handleParams.gravity = Gravity.CENTER_HORIZONTAL;
        handleParams.topMargin = dp(activity, 12);
        handleParams.bottomMargin = dp(activity, 14);
        sheet.addView(handle, handleParams);

        // The heading scrolls with the evidence, so large fonts and landscape screens
        // cannot squeeze the actual evidence out between a fixed header and footer.
        ScrollView scroll = new ScrollView(activity);
        scroll.setFillViewport(false);
        scroll.setClipToPadding(false);
        scroll.setOverScrollMode(View.OVER_SCROLL_IF_CONTENT_SCROLLS);
        scroll.setVerticalScrollBarEnabled(true);
        LinearLayout body = new LinearLayout(activity);
        body.setOrientation(LinearLayout.VERTICAL);
        body.setPadding(dp(activity, 22), dp(activity, 2), dp(activity, 22), dp(activity, 20));
        scroll.addView(body, new ScrollView.LayoutParams(-1, -2));

        TextView eyebrow = text(activity, "EVIDENCE / 原始依据", 10, ACCENT, true);
        eyebrow.setLetterSpacing(0.12f);
        body.addView(eyebrow);
        TextView heading = text(activity, title == null ? "检测依据" : title, 23, TEXT, true);
        if (Build.VERSION.SDK_INT >= 28) heading.setAccessibilityHeading(true);
        add(body, heading, activity, 10);
        if (subtitle != null && !subtitle.trim().isEmpty()) {
            TextView description = text(activity, subtitle, 12, MUTED, false);
            description.setLineSpacing(dp(activity, 3), 1f);
            add(body, description, activity, 8);
        }
        View divider = new View(activity);
        divider.setBackgroundColor(BORDER);
        LinearLayout.LayoutParams dividerParams = new LinearLayout.LayoutParams(-1, dp(activity, 1));
        dividerParams.topMargin = dp(activity, 18);
        dividerParams.bottomMargin = dp(activity, 18);
        body.addView(divider, dividerParams);

        TextView evidence = text(activity, content == null ? "暂无可用依据。" : content, 13, TEXT, false);
        evidence.setTextIsSelectable(true);
        evidence.setLineSpacing(dp(activity, 4), 1f);
        evidence.setHorizontallyScrolling(false);
        if (monospace) {
            evidence.setTypeface(Typeface.MONOSPACE);
            evidence.setHyphenationFrequency(Layout.HYPHENATION_FREQUENCY_NONE);
        }
        body.addView(evidence, new LinearLayout.LayoutParams(-1, -2));
        sheet.addView(scroll, new LinearLayout.LayoutParams(-1, -2, 1f));

        LinearLayout actions = new LinearLayout(activity);
        actions.setOrientation(LinearLayout.HORIZONTAL);
        actions.setGravity(Gravity.CENTER_VERTICAL);
        actions.setPadding(dp(activity, 18), dp(activity, 12), dp(activity, 18), dp(activity, 16));
        if (secondaryAction != null && secondaryLabel != null && !secondaryLabel.trim().isEmpty()) {
            Button secondary = action(activity, secondaryLabel, false);
            secondary.setOnClickListener(v -> {
                dismiss(dialog);
                if (!canShow(activity)) return;
                try {
                    secondaryAction.run();
                } catch (RuntimeException error) {
                    Log.w("GpuCheck", "Cannot open secondary evidence panel", error);
                }
            });
            LinearLayout.LayoutParams secondaryParams = new LinearLayout.LayoutParams(0, -2, 1f);
            secondaryParams.setMarginEnd(dp(activity, 10));
            actions.addView(secondary, secondaryParams);
        }
        Button close = action(activity, "关闭", true);
        close.setOnClickListener(v -> dismiss(dialog));
        actions.addView(close, new LinearLayout.LayoutParams(0, -2, 1f));
        sheet.addView(actions, new LinearLayout.LayoutParams(-1, -2));
        dialog.setContentView(sheet);

        Window window = dialog.getWindow();
        if (window == null) return;
        window.setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));
        window.setGravity(Gravity.BOTTOM | Gravity.CENTER_HORIZONTAL);
        window.setDimAmount(0.64f);
        window.addFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND);
        window.clearFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN
                | WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS);
        window.setWindowAnimations(0);
        window.setNavigationBarColor(SURFACE);
        window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE);
        if (Build.VERSION.SDK_INT >= 30) window.setDecorFitsSystemWindows(true);
        if (Build.VERSION.SDK_INT >= 28) {
            WindowManager.LayoutParams attributes = window.getAttributes();
            attributes.layoutInDisplayCutoutMode = WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_NEVER;
            window.setAttributes(attributes);
        }
        // A floating, system-fitted window owns the bar padding. Constrain its size
        // to the safe Activity viewport rather than adding the same insets twice.
        sheet.setOnApplyWindowInsetsListener((view, insets) -> {
            sizeToViewport(activity, window, sheet);
            return insets;
        });

        Application application = activity.getApplication();
        Application.ActivityLifecycleCallbacks lifecycle = new Application.ActivityLifecycleCallbacks() {
            @Override public void onActivityCreated(Activity owner, Bundle state) { }
            @Override public void onActivityStarted(Activity owner) { }
            @Override public void onActivityResumed(Activity owner) { }
            @Override public void onActivityPaused(Activity owner) { }
            @Override public void onActivityStopped(Activity owner) {
                // The monitor clears its session when the screen is left; evidence must
                // not survive in a dialog and appear to be a fresh result on return.
                if (owner == activity) dismiss(dialog);
            }
            @Override public void onActivitySaveInstanceState(Activity owner, Bundle state) { }
            @Override public void onActivityDestroyed(Activity owner) {
                if (owner == activity) {
                    // A window removed by Android may not dispatch onDismiss.
                    application.unregisterActivityLifecycleCallbacks(this);
                    sheet.setOnApplyWindowInsetsListener(null);
                    dismiss(dialog);
                }
            }
        };
        dialog.setOnDismissListener(ignored -> {
            sheet.setOnApplyWindowInsetsListener(null);
            application.unregisterActivityLifecycleCallbacks(lifecycle);
        });
        application.registerActivityLifecycleCallbacks(lifecycle);
        try {
            if (!canShow(activity)) {
                application.unregisterActivityLifecycleCallbacks(lifecycle);
                return;
            }
            sizeToViewport(activity, window, sheet);
            dialog.show();
            window.getDecorView().setPadding(0, 0, 0, 0);
            sizeToViewport(activity, window, sheet);
            sheet.requestApplyInsets();
        } catch (RuntimeException error) {
            application.unregisterActivityLifecycleCallbacks(lifecycle);
            dismiss(dialog);
            Log.w("GpuCheck", "Cannot display evidence panel", error);
        }
    }

    private static void sizeToViewport(Activity activity, Window window, BoundedColumn sheet) {
        DisplayMetrics display = activity.getResources().getDisplayMetrics();
        int width = display.widthPixels;
        int height = display.heightPixels;
        if (Build.VERSION.SDK_INT >= 30) {
            WindowMetrics metrics = activity.getWindowManager().getCurrentWindowMetrics();
            Rect bounds = metrics.getBounds();
            android.graphics.Insets bars = metrics.getWindowInsets().getInsetsIgnoringVisibility(
                    WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
            width = bounds.width() - bars.left - bars.right;
            height = bounds.height() - bars.top - bars.bottom;
        } else {
            Rect visible = new Rect();
            activity.getWindow().getDecorView().getWindowVisibleDisplayFrame(visible);
            if (!visible.isEmpty()) {
                width = visible.width();
                height = visible.height();
            }
        }
        int panelWidth = Math.max(1, Math.min(dp(activity, 720), width));
        sheet.setMaximumHeight(Math.max(1, Math.round(height * 0.86f)));
        WindowManager.LayoutParams attributes = window.getAttributes();
        if (attributes.width != panelWidth || attributes.height != WindowManager.LayoutParams.WRAP_CONTENT) {
            window.setLayout(panelWidth, WindowManager.LayoutParams.WRAP_CONTENT);
        }
    }

    private static boolean canShow(Activity activity) {
        return activity != null && !activity.isFinishing() && !activity.isDestroyed();
    }

    private static void dismiss(Dialog dialog) {
        try {
            dialog.dismiss();
        } catch (IllegalArgumentException error) {
            // The activity's window may already have been removed during teardown.
            Log.w("GpuCheck", "Evidence window already removed", error);
        }
    }

    private static TextView text(Activity activity, CharSequence value, int size, int color, boolean bold) {
        TextView view = new TextView(activity);
        view.setText(value);
        view.setTextSize(size);
        view.setTextColor(color);
        view.setFontFeatureSettings("tnum");
        if (bold) view.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        return view;
    }

    private static Button action(Activity activity, String label, boolean primary) {
        Button button = new Button(activity);
        button.setText(label);
        button.setTextSize(14);
        button.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        button.setTextColor(primary ? SURFACE : TEXT);
        button.setAllCaps(false);
        button.setSingleLine(false);
        button.setMinWidth(0);
        button.setMinimumWidth(0);
        button.setMinHeight(dp(activity, 48));
        button.setMinimumHeight(dp(activity, 48));
        button.setPadding(dp(activity, 12), dp(activity, 12), dp(activity, 12), dp(activity, 12));
        button.setStateListAnimator(null);
        StateListDrawable states = new StateListDrawable();
        states.addState(new int[]{android.R.attr.state_pressed}, shape(activity,
                primary ? Color.rgb(194, 225, 119) : BORDER, primary ? ACCENT : MUTED, 12));
        states.addState(new int[]{android.R.attr.state_focused}, shape(activity,
                primary ? ACCENT : SURFACE, ACCENT, 12));
        states.addState(new int[]{}, shape(activity, primary ? ACCENT : SURFACE,
                primary ? ACCENT : BORDER, 12));
        button.setBackground(states);
        return button;
    }

    private static GradientDrawable panelBackground(Activity activity) {
        GradientDrawable shape = shape(activity, SURFACE, BORDER, 0);
        float radius = dp(activity, 24);
        shape.setCornerRadii(new float[]{radius, radius, radius, radius, 0, 0, 0, 0});
        return shape;
    }

    private static GradientDrawable shape(Activity activity, int fill, int stroke, int radius) {
        GradientDrawable background = new GradientDrawable();
        background.setColor(fill);
        background.setCornerRadius(dp(activity, radius));
        background.setStroke(dp(activity, 1), stroke);
        return background;
    }

    private static void add(LinearLayout parent, View child, Activity activity, int top) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-1, -2);
        params.topMargin = dp(activity, top);
        parent.addView(child, params);
    }

    private static int dp(Activity activity, float value) {
        return Math.round(value * activity.getResources().getDisplayMetrics().density);
    }

    private static final class BoundedColumn extends LinearLayout {
        private int maximumHeight = Integer.MAX_VALUE;

        BoundedColumn(Activity activity) { super(activity); }

        void setMaximumHeight(int height) {
            if (height == maximumHeight) return;
            maximumHeight = height;
            requestLayout();
        }

        @Override protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            int mode = MeasureSpec.getMode(heightMeasureSpec);
            int available = mode == MeasureSpec.UNSPECIFIED ? maximumHeight
                    : Math.min(maximumHeight, MeasureSpec.getSize(heightMeasureSpec));
            super.onMeasure(widthMeasureSpec, MeasureSpec.makeMeasureSpec(available, MeasureSpec.AT_MOST));
        }
    }
}
